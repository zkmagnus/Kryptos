//! The genesis block: an empty transaction set, empty commitment tree, the
//! limit target, and no proof of work. It is identified by hash, not
//! validated.

use protocol::block::{empty_header, tx_root, Block, BlockHash};
use storage::tree::CommitmentTree;

use crate::params::ChainParams;

/// The genesis block of a network.
pub fn genesis(params: &ChainParams) -> Block {
    genesis_with_tree(params).0
}

/// The genesis block and its empty commitment tree.
pub fn genesis_with_tree(params: &ChainParams) -> (Block, CommitmentTree) {
    let transactions: Vec<protocol::transaction::Transaction> = Vec::new();
    let tree = CommitmentTree::empty();
    let mut header = empty_header(0, BlockHash::ZERO, tree.root());
    header.timestamp = params.genesis_timestamp;
    header.target = params.pow_limit.to_compact();
    header.tx_root = tx_root(core::iter::empty());
    header.body_root = protocol::body_tree::empty_body_root();
    header.history_root = protocol::header_tree::empty_root();
    (Block::new(header, transactions), tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic_and_has_no_initial_allocation() {
        let a = genesis(&ChainParams::mainnet());
        assert_eq!(a, genesis(&ChainParams::mainnet()));
        assert_eq!(a.header().height, 0);
        assert_eq!(a.check_tx_root(), Ok(()));
        assert!(ChainParams::test().upgrades_are_well_formed());
        assert!(a.transactions().is_empty());
    }

    #[test]
    fn networks_have_different_genesis_blocks() {
        assert_ne!(
            genesis(&ChainParams::mainnet()).hash(),
            genesis(&ChainParams::test()).hash()
        );
    }

    #[test]
    fn version_one_reset_has_new_genesis_hashes() {
        for (params, old_timestamp) in [
            (ChainParams::mainnet(), 1_793_700_000),
            (ChainParams::test(), 1_793_700_001),
        ] {
            let current = genesis(&params);
            let previous_params = ChainParams {
                genesis_timestamp: old_timestamp,
                ..params
            };
            let previous = genesis(&previous_params);
            let mut previous_v2 = previous.header().clone();
            previous_v2.version = 2;

            assert_ne!(current.hash(), previous.hash());
            assert_ne!(current.hash(), previous_v2.hash());
        }
    }

    #[test]
    fn both_networks_start_without_transactions_or_allocated_coins() {
        for params in [ChainParams::mainnet(), ChainParams::test()] {
            let (block, tree) = genesis_with_tree(&params);
            assert_eq!(block.header().commitment_root, tree.root());
            assert!(block.transactions().is_empty());
            assert_eq!(tree.size(), 0);
        }
    }
}
