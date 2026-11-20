//! Composite state-root API, delegated to the protocol's canonical formula.

use protocol::transaction::Anchor;

/// Version of the composite state-root encoding.
pub use protocol::state::STATE_COMMITMENT_VERSION;

/// Computes the chain- and version-separated post-block state root.
pub fn state_root(
    chain_id: &[u8; 32],
    height: u32,
    commitment_root: Anchor,
    commitment_count: u64,
    nullifier_root: Anchor,
    nullifier_count: u64,
) -> Anchor {
    protocol::state::state_root(
        chain_id,
        height,
        commitment_root,
        commitment_count,
        nullifier_root,
        nullifier_count,
    )
}
