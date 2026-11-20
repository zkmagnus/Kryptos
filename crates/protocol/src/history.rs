//! Public statement carried by one recursive history transition proof.
//!
//! This type defines the values a future `HistoryStep` circuit must bind. It
//! does not claim that a proof or deferred accumulator has been verified.

use crate::block::BlockHeader;
use crate::consensus::BLOCK_VERSION;
use crate::transaction::Anchor;

/// Public inputs for a single history transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryPublic {
    /// Network identifier used by state and circuit domains.
    pub chain_id: [u8; 32],
    /// Digest of the consensus rules and pinned transaction verifying key.
    pub rules_digest: [u8; 32],
    /// Version of the history circuit statement.
    pub circuit_version: u32,
    /// Transition digest of the parent header, excluding its PoW solution.
    pub parent_transition_hash: [u8; 32],
    /// Transition digest of this header, excluding its PoW solution.
    pub transition_hash: [u8; 32],
    /// Height committed by this transition.
    pub height: u32,
    /// Composite state root before this transition.
    pub parent_state_root: Anchor,
    /// Composite state root after this transition.
    pub state_root: Anchor,
    /// Parent cumulative work as four limbs for circuit range checks.
    pub parent_work: [u64; 4],
    /// Child cumulative work as four limbs for circuit range checks.
    pub work: [u64; 4],
    /// Compact target committed by the child header.
    pub target: u32,
    /// Opaque deferred-accumulator output; its final encoding is unresolved.
    pub acc_out: [u8; 32],
}

impl HistoryPublic {
    /// Constructs the statement only for a current-version parent/child pair.
    ///
    /// Returns `None` when the headers do not form one consecutive current-version
    /// transition. Work limbs and accumulator bytes are carried as provided;
    /// their circuit constraints and accumulator encoding are not implemented.
    pub fn from_headers(
        parent: &BlockHeader,
        child: &BlockHeader,
        chain_id: [u8; 32],
        rules_digest: [u8; 32],
        circuit_version: u32,
        parent_work: [u64; 4],
        work: [u64; 4],
        acc_out: [u8; 32],
    ) -> Option<Self> {
        if parent.version != BLOCK_VERSION
            || child.version != BLOCK_VERSION
            || child.prev_hash != parent.hash()
            || parent.height.checked_add(1) != Some(child.height)
        {
            return None;
        }

        Some(Self {
            chain_id,
            rules_digest,
            circuit_version,
            parent_transition_hash: parent.transition_hash(),
            transition_hash: child.transition_hash(),
            height: child.height,
            parent_state_root: parent.state_root,
            state_root: child.state_root,
            parent_work,
            work,
            target: child.target,
            acc_out,
        })
    }

    /// Checks that the statement's header-bound fields match this header edge.
    ///
    /// This is a consistency check, not proof verification, work validation,
    /// or an ancestry/canonical-chain check.
    pub fn matches_headers(&self, parent: &BlockHeader, child: &BlockHeader) -> bool {
        parent.version == BLOCK_VERSION
            && child.version == BLOCK_VERSION
            && child.prev_hash == parent.hash()
            && parent.height.checked_add(1) == Some(child.height)
            && self.parent_transition_hash == parent.transition_hash()
            && self.transition_hash == child.transition_hash()
            && self.height == child.height
            && self.parent_state_root == parent.state_root
            && self.state_root == child.state_root
            && self.target == child.target
    }
}
