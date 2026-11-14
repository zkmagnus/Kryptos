//! The chain: imports blocks onto the best chain, keeping side chains and
//! reorganizing to whichever has the most work.

use crypto::hash::{blake2b_short, RULES};
use protocol::block::{Block, BlockHash};
use protocol::bytes::Writer;
use rand_core::{CryptoRng, RngCore};
use storage::store::{Store, Tip};
use transaction_proof::VerifyingKey;

use crate::genesis::genesis_with_tree;
use crate::params::ChainParams;
use crate::pow::RandomXPow;
use crate::target::{Target, U512};
use crate::validate::Validator;
use crate::{Error, Result};

/// What importing a block did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Import {
    /// The block was already stored.
    AlreadyKnown,
    /// The block extended the tip.
    Extended,
    /// The block was stored on a side chain with no more work than ours.
    SideChain,
    /// The block's chain had more work; the tip moved to it.
    Reorganized {
        /// Blocks removed from the old best chain, tip first, so their
        /// transactions can be readmitted to the mempool.
        reverted: Vec<Block>,
        /// Blocks applied from the new best chain.
        applied: u32,
    },
}

/// A chain over a store.
pub struct Chain {
    store: Store,
    params: ChainParams,
    pow: RandomXPow,
    vk: VerifyingKey,
}

impl Chain {
    /// Opens the chain, applying genesis if the store is empty.
    ///
    /// # Errors
    /// Fails on invalid issuance parameters, a storage error, or a store
    /// holding a different genesis.
    pub fn new(store: Store, params: ChainParams, vk: VerifyingKey) -> Result<Self> {
        let (expected, tree) = genesis_with_tree(&params);
        match store.hash_at(0)? {
            None => store.apply(&expected, &tree)?,
            Some(hash) if hash == expected.hash() => {}
            Some(_) => return Err(Error::InvalidBlock("store belongs to another network")),
        }
        // Genesis does not change at an upgrade, so blocks applied by a
        // binary with another schedule or circuit would pass unnoticed;
        // the digest refuses such a store instead of trusting it.
        let digest = rules_digest(&params, &vk);
        match store.rules_digest()? {
            // Only a store holding nothing but genesis may be stamped: any
            // history without a digest was validated by a binary that did
            // not record its rules, so it cannot be trusted.
            None if store.tip()?.is_some_and(|t| t.height > 0) => return Err(Error::RulesMismatch),
            None => store.set_rules_digest(&digest)?,
            Some(recorded) if recorded == digest => {}
            Some(_) => return Err(Error::RulesMismatch),
        }
        Ok(Self {
            store,
            params,
            pow: RandomXPow::new(params.randomx_key)?,
            vk,
        })
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The parameters.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The proof of work.
    pub fn pow(&self) -> &RandomXPow {
        &self.pow
    }

    /// The circuit verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    /// The current tip.
    ///
    /// # Errors
    /// Fails on a storage error.
    pub fn tip(&self) -> Result<Tip> {
        self.store.tip()?.ok_or(Error::InvalidBlock("no genesis"))
    }

    /// Imports a block: extends the tip, stores a side-chain block, or
    /// reorganizes when the side chain has more work.
    ///
    /// # Errors
    /// Returns [`Error::Orphan`] if the parent is unknown, or the first
    /// validation failure. A failed reorganization restores the old chain.
    pub fn import(
        &self,
        block: &Block,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Import> {
        if self.store.block(&block.hash())?.is_some() {
            return Ok(Import::AlreadyKnown);
        }
        let tip = self.tip()?;
        if block.header().prev_hash == tip.hash {
            self.validator(now)
                .validate_and_apply(&self.store, block, rng)?;
            return Ok(Import::Extended);
        }
        if self.store.block(&block.header().prev_hash)?.is_none() {
            return Err(Error::Orphan);
        }
        // Side-chain blocks are stored before their chain state can be
        // checked, so require everything else first: the header against
        // its own ancestry and proof of work, or a peer could fill the
        // disk with cheaply made garbage that has a known parent, and the
        // signatures and proofs, or a peer could store an unverifiable
        // body under the valid header hash and the real body would then
        // be refused as already known.
        self.validator(now)
            .check_side_chain_block(&self.store, block, rng)?;
        let branch = self.branch_to_main_chain(block)?;
        let fork_height = branch
            .first()
            .map_or(tip.height, |b| b.header().height.saturating_sub(1));
        if fork_height < self.params.last_checkpoint_height().min(tip.height) {
            return Err(Error::InvalidBlock("reorganization below a checkpoint"));
        }
        if tip.height.saturating_sub(fork_height) > self.params.max_reorg_depth {
            return Err(Error::InvalidBlock("reorganization too deep"));
        }
        let branch_work = chain_work(&branch)?;
        let main_work = chain_work(&self.main_blocks_above(fork_height, tip.height)?)?;
        if branch_work <= main_work {
            return Ok(Import::SideChain);
        }
        self.reorganize(fork_height, &branch, now, rng)
    }

    fn validator(&self, now: u64) -> Validator<'_> {
        Validator {
            params: &self.params,
            pow: &self.pow,
            vk: &self.vk,
            now,
        }
    }

    /// The side-chain blocks from the fork point up to `block`, oldest
    /// first. The fork point is the first ancestor on the main chain.
    fn branch_to_main_chain(&self, block: &Block) -> Result<Vec<Block>> {
        let mut branch = vec![block.clone()];
        loop {
            let header = branch.last().map(Block::header).ok_or(Error::Orphan)?;
            let parent_height = header
                .height
                .checked_sub(1)
                .ok_or(Error::InvalidBlock("branch below genesis"))?;
            if self.store.hash_at(parent_height)? == Some(header.prev_hash) {
                break;
            }
            let parent = self.store.block(&header.prev_hash)?.ok_or(Error::Orphan)?;
            branch.push(parent);
        }
        branch.reverse();
        Ok(branch)
    }

    /// Main-chain blocks strictly above `fork_height` up to `tip_height`.
    fn main_blocks_above(&self, fork_height: u32, tip_height: u32) -> Result<Vec<Block>> {
        (fork_height.saturating_add(1)..=tip_height)
            .map(|height| {
                let hash = self
                    .store
                    .hash_at(height)?
                    .ok_or(Error::InvalidBlock("height index gap"))?;
                self.store
                    .block(&hash)?
                    .ok_or(Error::InvalidBlock("block missing"))
            })
            .collect()
    }

    /// Reverts to `fork_height`, applies `branch`, and restores the old
    /// chain if any branch block is invalid.
    fn reorganize(
        &self,
        fork_height: u32,
        branch: &[Block],
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Import> {
        let mut reverted = Vec::new();
        while self.tip()?.height > fork_height {
            reverted.push(self.store.revert()?);
        }
        let validator = self.validator(now);
        let mut applied = 0u32;
        for block in branch {
            if let Err(error) = validator.validate_and_apply(&self.store, block, rng) {
                for _ in 0..applied {
                    self.store.revert()?;
                }
                for old in reverted.iter().rev() {
                    validator.validate_and_apply(&self.store, old, rng)?;
                }
                return Err(error);
            }
            applied = applied.saturating_add(1);
        }
        Ok(Import::Reorganized { reverted, applied })
    }
}

/// Revision marker for the current consensus rules. The chain is reset when
/// consensus changes, so this remains at the initial revision.
pub const CONSENSUS_REVISION: u32 = 1;

/// Digest of everything that decides whether an applied block was valid:
/// [`CONSENSUS_REVISION`], every consensus parameter, the genesis branch,
/// the upgrade schedule, the checkpoints and the verifying key.
pub fn rules_digest(params: &ChainParams, vk: &VerifyingKey) -> [u8; 32] {
    let mut w = Writer::default();
    w.put(&CONSENSUS_REVISION.to_le_bytes());
    w.put(b"rhombus-randomx-v1-native-transfer-public-byte-fee-per-tx-binding-50-coin-halving");
    w.put(&protocol::consensus::TX_VERSION.to_le_bytes());
    w.put(&[
        protocol::consensus::TRANSFER_KIND,
        protocol::consensus::COINBASE_KIND,
    ]);
    w.put(&[protocol::consensus::BLOCK_VERSION]);
    w.put(&protocol::consensus::BLOCK_EMISSION_START.to_le_bytes());
    w.put(&protocol::consensus::TAIL_BLOCK_EMISSION.to_le_bytes());
    w.put(&protocol::consensus::EMISSION_INTERVAL.to_le_bytes());
    w.put(&protocol::consensus::EMISSION_HALVINGS_TO_TAIL.to_le_bytes());
    w.put(
        &u64::try_from(params.randomx_key.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    w.put(params.randomx_key);
    w.put(&params.pow_limit.to_compact().to_le_bytes());
    // Only written when set, so a network that never changed its limit
    // keeps the digest its stores were stamped with.
    if let Some(change) = params.pow_limit_change {
        w.put(&change.height.to_le_bytes());
        w.put(&change.limit.to_compact().to_le_bytes());
    }
    w.put(&params.block_interval.to_le_bytes());
    w.put(
        &u64::try_from(params.difficulty_window)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    w.put(&params.genesis_timestamp.to_le_bytes());
    w.put(&params.anchor_max_age.to_le_bytes());
    w.put(&params.max_future_seconds.to_le_bytes());
    w.put(&params.max_reorg_depth.to_le_bytes());
    w.put(&params.genesis_branch.to_bytes());
    for upgrade in params.upgrades {
        w.put(&upgrade.height.to_le_bytes());
        w.put(&upgrade.branch.to_bytes());
    }
    for checkpoint in params.checkpoints {
        w.put(&checkpoint.height.to_le_bytes());
        w.put(checkpoint.hash.as_bytes());
    }
    blake2b_short(
        RULES,
        &[&w.into_bytes(), vk.pinned_description().as_bytes()],
    )
}

/// Summed work of `blocks`.
fn chain_work(blocks: &[Block]) -> Result<U512> {
    blocks.iter().try_fold(U512::zero(), |acc, block| {
        let work = Target::from_compact(block.header().target)?.work();
        // A valid target contributes at most 2^255 work, and a chain has
        // at most u32::MAX heights, so the sum fits in 288 bits. Keep a
        // checked operation here so a future wider height/work rule cannot
        // silently turn distinct chains into equal saturated totals.
        acc.checked_add(U512::from_big_endian(&work.to_big_endian()))
            .ok_or(Error::InvalidBlock("chain work overflow"))
    })
}

/// Hash of the block at `height` on the main chain, for tests and tools.
///
/// # Errors
/// Fails on a storage error.
pub fn hash_at(chain: &Chain, height: u32) -> Result<Option<BlockHash>> {
    Ok(chain.store.hash_at(height)?)
}

#[cfg(test)]
mod tests {
    use protocol::consensus::BranchId;

    use super::*;
    use crate::params::Upgrade;

    static ONE_UPGRADE: [Upgrade; 1] = [Upgrade {
        height: 7,
        branch: BranchId::new(3),
    }];

    #[test]
    fn rules_digest_covers_the_branch_and_the_schedule() {
        let vk = VerifyingKey::build().unwrap();
        let base = ChainParams::test();
        assert_eq!(rules_digest(&base, &vk), rules_digest(&base, &vk));
        let scheduled = ChainParams {
            upgrades: &ONE_UPGRADE,
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&scheduled, &vk));
        let other_limit = ChainParams {
            max_reorg_depth: base.max_reorg_depth + 1,
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&other_limit, &vk));
        let other_branch = ChainParams {
            genesis_branch: BranchId::new(4),
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&other_branch, &vk));
        let eased = ChainParams {
            pow_limit_change: Some(crate::params::PowLimitChange {
                height: 7,
                limit: base.pow_limit,
            }),
            ..base
        };
        let later = ChainParams {
            pow_limit_change: eased
                .pow_limit_change
                .map(|c| crate::params::PowLimitChange { height: 8, ..c }),
            ..base
        };
        assert_ne!(
            rules_digest(&base, &vk),
            rules_digest(&eased, &vk),
            "a store built before a limit change is refused"
        );
        assert_ne!(rules_digest(&eased, &vk), rules_digest(&later, &vk));
        assert_ne!(
            rules_digest(&base, &vk),
            rules_digest(&ChainParams::mainnet(), &vk),
            "networks differ"
        );
    }
}
