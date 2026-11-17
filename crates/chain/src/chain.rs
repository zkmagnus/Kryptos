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
use crate::target::ChainWork;
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
            None => store.apply(&expected, &tree, &ChainWork::ZERO.to_be_bytes())?,
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
        let chain = Self {
            store,
            params,
            pow: RandomXPow::new(params.randomx_key)?,
            vk,
        };
        if chain.chainwork(&expected.hash())? != ChainWork::ZERO {
            return Err(Error::InvalidBlock("genesis chain work must be zero"));
        }
        chain.recover_reorg()?;
        chain.tip_chainwork()?;
        Ok(chain)
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

    /// Indexed cumulative work of a validated block. Genesis contributes zero:
    /// its fixed header is a network anchor, not a mined proof of work.
    ///
    /// # Errors
    /// Fails if the block has no work index entry or the database cannot be read.
    pub fn chainwork(&self, hash: &BlockHash) -> Result<ChainWork> {
        self.store
            .chainwork(hash)?
            .map(ChainWork::from_be_bytes)
            .ok_or(Error::InvalidBlock("block chain work missing"))
    }

    /// The current tip's cumulative work.
    ///
    /// # Errors
    /// Fails on a missing tip or work index entry, or a storage read error.
    pub fn tip_chainwork(&self) -> Result<ChainWork> {
        self.chainwork(&self.tip()?.hash)
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
        self.recover_reorg()?;
        if self.store.hash_at(block.header().height)? == Some(block.hash()) {
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
        // Keep the first accepted tip on equal work; block hashes never
        // influence the tie. Every indexed value came from a validated target.
        if self.chainwork(&block.hash())? <= self.chainwork(&tip.hash)? {
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

    /// Rolls an interrupted reorg back to its original, previously validated chain.
    /// Each step is durable and repeatable if recovery itself is interrupted.
    fn recover_reorg(&self) -> Result<()> {
        let Some((original, fork)) = self.store.pending_reorg()? else {
            return Ok(());
        };
        let fork_block = self
            .store
            .block(&fork)?
            .ok_or(Error::InvalidBlock("reorg fork missing"))?;
        let fork_height = fork_block.header().height;
        let mut old = Vec::new();
        let mut hash = original;
        while hash != fork {
            let block = self
                .store
                .block(&hash)?
                .ok_or(Error::InvalidBlock("reorg original block missing"))?;
            hash = block.header().prev_hash;
            old.push(block);
        }
        while self.tip()?.height > fork_height {
            self.store.revert()?;
        }
        if self.tip()?.hash != fork {
            return Err(Error::InvalidBlock("reorg fork mismatch"));
        }
        let mut tree = self.store.tree()?;
        for block in old.iter().rev() {
            for tx in protocol::tree_order::tree_transactions(block)? {
                for action in tx.actions() {
                    tree.append(action.body().cmx())?;
                }
            }
            if tree.root() != block.header().commitment_root {
                return Err(Error::InvalidBlock("recovery commitment root mismatch"));
            }
            self.store
                .apply(block, &tree, &self.chainwork(&block.hash())?.to_be_bytes())?;
        }
        self.store.finish_reorg()?;
        Ok(())
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
        let fork = self.store.hash_at(fork_height)?.ok_or(Error::Orphan)?;
        self.store.begin_reorg(self.tip()?.hash, fork)?;
        let mut reverted = Vec::new();
        while self.tip()?.height > fork_height {
            reverted.push(self.store.revert()?);
        }
        let validator = self.validator(now);
        let mut applied = 0u32;
        for block in branch {
            if let Err(error) = validator.validate_and_apply(&self.store, block, rng) {
                self.recover_reorg()?;
                return Err(error);
            }
            applied = applied.saturating_add(1);
        }
        self.store.finish_reorg()?;
        if let Some(floor) = self.tip()?.height.checked_sub(self.params.max_reorg_depth) {
            self.store.prune_frontiers_below(floor)?;
        }
        Ok(Import::Reorganized { reverted, applied })
    }
}

/// Revision marker for the current consensus rules. Revision 2 requires exact
/// compact difficulty and checked 256-bit cumulative work.
pub const CONSENSUS_REVISION: u32 = 2;

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

/// Hash of the block at `height` on the main chain, for tests and tools.
///
/// # Errors
/// Fails on a storage error.
pub fn hash_at(chain: &Chain, height: u32) -> Result<Option<BlockHash>> {
    Ok(chain.store.hash_at(height)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn reopening_recovers_every_interrupted_reorg_phase() {
        // Model durable boundaries without proof generation: these empty blocks
        // represent previously validated store state, not network imports.
        for phase in 0..4 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("chain.redb");
            let params = ChainParams::test();
            let chain = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            let fork = chain.tip().unwrap().hash;
            let tree = chain.store.tree().unwrap();
            let first = Block::new(protocol::block::empty_header(1, fork, tree.root()), vec![]);
            chain.store.apply(&first, &tree, &[1; 32]).unwrap();
            let second = Block::new(
                protocol::block::empty_header(2, first.hash(), tree.root()),
                vec![],
            );
            chain.store.apply(&second, &tree, &[2; 32]).unwrap();
            chain.store.begin_reorg(second.hash(), fork).unwrap();
            if phase >= 1 {
                chain.store.revert().unwrap();
            }
            if phase >= 2 {
                chain.store.revert().unwrap();
            }
            if phase >= 3 {
                let mut header = first.header().clone();
                header.timestamp += 1;
                chain
                    .store
                    .apply(&Block::new(header, vec![]), &tree, &[3; 32])
                    .unwrap();
            }
            chain.store.prune_frontiers_below(100).unwrap();
            assert!(chain.store.tree_at(0).unwrap().is_some());
            drop(chain);
            let recovered = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            assert_eq!(recovered.tip().unwrap().hash, second.hash());
            assert_eq!(recovered.store.hash_at(1).unwrap(), Some(first.hash()));
            assert_eq!(recovered.store.tree().unwrap().root(), tree.root());
            assert!(recovered.store.pending_reorg().unwrap().is_none());
            drop(recovered);
            let again = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            assert_eq!(again.tip().unwrap().hash, second.hash());
        }
    }

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
