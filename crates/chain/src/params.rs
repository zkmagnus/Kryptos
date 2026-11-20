//! Chain parameters: everything a network fixes at launch.

use protocol::address::Network;
use protocol::block::BlockHash;
use protocol::consensus::BranchId;
use protocol::transaction::Anchor;

use crate::target::{ChainWork, Target};

/// A block every node must agree on: no chain that disagrees with it is
/// accepted, and no reorganization may revert it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Height.
    pub height: u32,
    /// Hash of the block at that height.
    pub hash: BlockHash,
    /// Cumulative validated work at the checkpoint.
    pub work: crate::target::ChainWork,
    /// Canonical state root committed by the checkpoint header.
    pub state_root: Anchor,
}

impl Checkpoint {
    /// Whether a header and validated work match this network trust anchor.
    pub fn matches(&self, header: &protocol::block::BlockHeader, work: ChainWork) -> bool {
        self.height == header.height
            && self.hash == header.hash()
            && self.work == work
            && self.state_root == header.state_root
    }
}

// Generated from deterministic testnet genesis by the checkpoint generator.
const TESTNET_CHECKPOINTS: [Checkpoint; 1] = [Checkpoint {
    height: 0,
    hash: BlockHash::from_bytes([
        0xc7, 0x97, 0xb0, 0x03, 0x16, 0x7b, 0x16, 0xca, 0xba, 0x24, 0x2e, 0x3d, 0x1c, 0x33, 0x20,
        0x9b, 0x01, 0x03, 0xdb, 0xef, 0xe2, 0xbf, 0xa7, 0xcc, 0x7b, 0x82, 0x03, 0x3c, 0x8f, 0x21,
        0x4a, 0x06,
    ]),
    work: crate::target::ChainWork::ZERO,
    state_root: Anchor::from_base(crypto::pallas::Base::zero()),
}];

/// A scheduled change of consensus rules: from `height` on, blocks are
/// validated under `branch`. Rule changes in code are gated on
/// [`ChainParams::branch_at`]; the new branch id alone already invalidates
/// every transaction signed for the old rules. See `docs/upgrades.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upgrade {
    /// First height validated under the new rules.
    pub height: u32,
    /// The rules' identifier, bound into every sighash from then on.
    pub branch: BranchId,
}

/// A one-time change of the easiest allowed target: from `height` on,
/// [`ChainParams::pow_limit_at`] is `limit` instead of
/// [`ChainParams::pow_limit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowLimitChange {
    /// First height whose target is bounded by `limit`.
    pub height: u32,
    /// The easiest allowed target from then on.
    pub limit: Target,
}

/// The constants of one network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// RandomX key that separates this network's proof-of-work domain.
    pub randomx_key: &'static [u8],
    /// The easiest allowed target at genesis; see [`Self::pow_limit_at`].
    pub pow_limit: Target,
    /// A later easiest allowed target, if the network changed it.
    pub pow_limit_change: Option<PowLimitChange>,
    /// Target seconds between blocks.
    pub block_interval: u64,
    /// Blocks averaged by the difficulty rule.
    pub difficulty_window: usize,
    /// Timestamp of the genesis block.
    pub genesis_timestamp: u64,
    /// Blocks whose commitment roots remain valid anchors.
    pub anchor_max_age: u32,
    /// Seconds a block timestamp may run ahead of local time.
    pub max_future_seconds: u64,
    /// Deepest reorganization a node accepts; older frontiers are pruned.
    pub max_reorg_depth: u32,
    /// Known-good blocks, ascending by height.
    pub checkpoints: &'static [Checkpoint],
    /// How addresses for this network are written.
    pub address_network: Network,
    /// The consensus branch from genesis until the first upgrade. Differs
    /// per network so a transaction for one is never valid on another.
    pub genesis_branch: BranchId,
    /// Scheduled upgrades, ascending by height, all above genesis.
    pub upgrades: &'static [Upgrade],
}

const MAIN_EMISSION_UPGRADES: [Upgrade; 1] = [Upgrade {
    height: 1,
    branch: BranchId::new(0x4d41_5231),
}];

const TEST_EMISSION_UPGRADES: [Upgrade; 1] = [Upgrade {
    height: 1,
    branch: BranchId::new(0x5445_5231),
}];

impl ChainParams {
    /// The checkpoint at `height`, if any.
    pub fn checkpoint_at(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

    /// Height of the highest checkpoint, or zero.
    pub fn last_checkpoint_height(&self) -> u32 {
        self.checkpoints.last().map_or(0, |c| c.height)
    }

    /// The easiest allowed target for the block at `height`.
    pub fn pow_limit_at(&self, height: u32) -> Target {
        match self.pow_limit_change {
            Some(change) if height >= change.height => change.limit,
            _ => self.pow_limit,
        }
    }

    /// The consensus branch in force at `height`: that of the last upgrade
    /// activated at or below it, or the genesis branch.
    pub fn branch_at(&self, height: u32) -> BranchId {
        self.upgrades
            .iter()
            .rev()
            .find(|u| u.height <= height)
            .map_or(self.genesis_branch, |u| u.branch)
    }

    /// Whether the upgrade schedule is well formed: ascending heights,
    /// none at genesis, and every branch distinct from the others and
    /// from the genesis branch.
    pub fn upgrades_are_well_formed(&self) -> bool {
        let ascending = self.upgrades.windows(2).all(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(a, b)| a.height < b.height)
        });
        let above_genesis = self.upgrades.iter().all(|u| u.height > 0);
        let distinct = self.upgrades.iter().enumerate().all(|(i, u)| {
            u.branch != self.genesis_branch
                && !self.upgrades.iter().take(i).any(|o| o.branch == u.branch)
        });
        ascending && above_genesis && distinct
    }
}

impl ChainParams {
    /// Provisional main network parameters.
    ///
    /// # Panics
    /// Never: the constants are valid by construction and checked in tests.
    #[allow(clippy::expect_used)]
    pub fn mainnet() -> Self {
        Self {
            randomx_key: b"Kryptos Mainnet RandomX v1",
            pow_limit: Target::from_compact(0x207f_ffff).expect("valid compact target"),
            pow_limit_change: None,
            block_interval: 120,
            // A 100-block LWMA window spans about 3 hours 20 minutes
            // at the two-minute target.
            difficulty_window: 100,
            // Keep the v1 reset distinct from earlier development genesis hashes.
            genesis_timestamp: 1_793_700_002,
            anchor_max_age: 100,
            max_future_seconds: 2 * 60 * 60,
            max_reorg_depth: 50,
            checkpoints: &[],
            address_network: Network::Main,
            genesis_branch: BranchId::new(0x4d41_494e),
            upgrades: &MAIN_EMISSION_UPGRADES,
        }
    }

    /// Parameters for tests and the local development network.
    ///
    /// # Panics
    /// Never: the constants are valid by construction.
    #[allow(clippy::expect_used)]
    pub fn test() -> Self {
        Self {
            randomx_key: b"Kryptos Testnet RandomX v1",
            pow_limit: Target::from_compact(0x207f_ffff).expect("valid compact target"),
            pow_limit_change: None,
            // Long enough that the difficulty rule demands several nonces
            // per block; with a trivial target block finding is deterministic
            // and the miner that started first wins every block.
            block_interval: 5,
            difficulty_window: 6,
            // Keep the v1 reset distinct from earlier development genesis hashes.
            genesis_timestamp: 1_793_700_003,
            anchor_max_age: 100,
            max_future_seconds: 2 * 60 * 60,
            max_reorg_depth: 50,
            checkpoints: &TESTNET_CHECKPOINTS,
            address_network: Network::Test,
            genesis_branch: BranchId::new(0x5445_5354),
            upgrades: &TEST_EMISSION_UPGRADES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEDULE: [Upgrade; 2] = [
        Upgrade {
            height: 10,
            branch: BranchId::new(1),
        },
        Upgrade {
            height: 20,
            branch: BranchId::new(2),
        },
    ];

    fn with_schedule(upgrades: &'static [Upgrade]) -> ChainParams {
        ChainParams {
            upgrades,
            ..ChainParams::test()
        }
    }

    #[test]
    fn branch_changes_exactly_at_each_activation_height() {
        let params = with_schedule(&SCHEDULE);
        let genesis = params.genesis_branch;
        assert_eq!(params.branch_at(0), genesis);
        assert_eq!(params.branch_at(9), genesis);
        assert_eq!(params.branch_at(10), BranchId::new(1));
        assert_eq!(params.branch_at(19), BranchId::new(1));
        assert_eq!(params.branch_at(20), BranchId::new(2));
        assert_eq!(params.branch_at(u32::MAX), BranchId::new(2));
        assert!(params.upgrades_are_well_formed());
    }

    #[test]
    fn malformed_schedules_are_detected() {
        static UNORDERED: [Upgrade; 2] = [SCHEDULE[1], SCHEDULE[0]];
        static AT_GENESIS: [Upgrade; 1] = [Upgrade {
            height: 0,
            branch: BranchId::new(1),
        }];
        static REUSES_GENESIS_BRANCH: [Upgrade; 1] = [Upgrade {
            height: 5,
            branch: BranchId::new(0x5445_5354),
        }];
        static REPEATED: [Upgrade; 2] = [
            SCHEDULE[0],
            Upgrade {
                height: 30,
                ..SCHEDULE[0]
            },
        ];
        for bad in [
            &UNORDERED[..],
            &AT_GENESIS[..],
            &REUSES_GENESIS_BRANCH[..],
            &REPEATED[..],
        ] {
            assert!(!with_schedule(bad).upgrades_are_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn networks_have_distinct_branches_and_well_formed_schedules() {
        let networks = [ChainParams::mainnet(), ChainParams::test()];
        let mut all: Vec<BranchId> = networks
            .iter()
            .flat_map(|p| {
                std::iter::once(p.genesis_branch).chain(p.upgrades.iter().map(|u| u.branch))
            })
            .collect();
        let count = all.len();
        all.sort_by_key(|b| b.to_bytes());
        all.dedup();
        assert_eq!(all.len(), count, "a branch id is shared between networks");
        for p in networks {
            assert!(p.upgrades_are_well_formed());
        }
    }

    #[test]
    fn both_networks_limit_reorganizations_to_fifty_blocks() {
        for params in [ChainParams::mainnet(), ChainParams::test()] {
            assert_eq!(params.max_reorg_depth, 50);
        }
    }

    #[test]
    fn networks_write_addresses_differently() {
        assert_ne!(
            ChainParams::mainnet().address_network,
            ChainParams::test().address_network
        );
    }

    #[test]
    fn limits_are_exactly_representable_in_compact_form() {
        for p in [ChainParams::mainnet(), ChainParams::test()] {
            for limit in [p.pow_limit, p.pow_limit_at(u32::MAX)] {
                assert_eq!(Target::from_compact(limit.to_compact()).unwrap(), limit);
            }
        }
    }

    #[test]
    fn mainnet_and_testnet_share_the_initial_pow_limit() {
        let main = ChainParams::mainnet();
        let test = ChainParams::test();
        assert_eq!(main.pow_limit.to_compact(), 0x207f_ffff);
        assert_eq!(main.pow_limit_at(0), test.pow_limit);
        assert_eq!(main.pow_limit_at(11), test.pow_limit);
        assert_eq!(test.pow_limit_at(u32::MAX), test.pow_limit);
        assert_eq!(main.pow_limit_at(u32::MAX), main.pow_limit);
    }

    #[test]
    fn both_networks_start_at_about_one_solution_in_two() {
        let main = ChainParams::mainnet();
        // 2^256 / limit, the expected solutions per block at the limit.
        let per_block = Target::MAX.as_u256() / main.pow_limit.as_u256();
        assert_eq!(per_block, crate::target::U256::from(2u64));
        assert_eq!(main.pow_limit, ChainParams::test().pow_limit);
    }

    #[test]
    fn checkpoint_lookups_work_on_an_empty_and_a_filled_list() {
        static POINTS: [Checkpoint; 2] = [
            Checkpoint {
                height: 5,
                hash: BlockHash::ZERO,
                work: crate::target::ChainWork::ZERO,
                state_root: Anchor::from_base(crypto::pallas::Base::zero()),
            },
            Checkpoint {
                height: 9,
                hash: BlockHash::ZERO,
                work: crate::target::ChainWork::ZERO,
                state_root: Anchor::from_base(crypto::pallas::Base::zero()),
            },
        ];
        let params = ChainParams::test();
        assert_eq!(params.checkpoint_at(0).map(|c| c.height), Some(0));
        assert_eq!(params.last_checkpoint_height(), 0);
        let with = ChainParams {
            checkpoints: &POINTS,
            ..params
        };
        assert_eq!(with.checkpoint_at(9).map(|c| c.height), Some(9));
        assert_eq!(with.last_checkpoint_height(), 9);
    }

    #[test]
    fn mainnet_checkpoint_list_is_empty_and_testnet_genesis_checkpoint_is_exact() {
        assert!(ChainParams::mainnet().checkpoints.is_empty());
        let params = ChainParams::test();
        let checkpoint = params.checkpoint_at(0).unwrap();
        let genesis = crate::genesis::genesis(&params);
        assert!(checkpoint.matches(genesis.header(), ChainWork::ZERO));
    }

    #[test]
    fn mainnet_and_testnet_use_distinct_randomx_keys() {
        assert_ne!(
            ChainParams::test().randomx_key,
            ChainParams::mainnet().randomx_key
        );
        assert_eq!(
            ChainParams::test().pow_limit,
            ChainParams::mainnet().pow_limit
        );
    }
}
