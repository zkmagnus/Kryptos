//! Domain-separated commitments to the materialized chain state.

use crypto::pallas;

use crate::transaction::Anchor;

/// Version of the composite state-root encoding.
pub const STATE_COMMITMENT_VERSION: u32 = 1;

/// Computes the chain- and version-separated root for a post-block state.
///
/// The chain ID is split into four little-endian 64-bit limbs so no hash bytes
/// are reduced modulo the field before being committed.
pub fn state_root(
    chain_id: &[u8; 32],
    height: u32,
    commitment_root: Anchor,
    commitment_count: u64,
    nullifier_root: Anchor,
    nullifier_count: u64,
) -> Anchor {
    let mut limbs = [pallas::Base::from(0u64); 4];
    for (limb, chunk) in limbs.iter_mut().zip(chain_id.chunks_exact(8)) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        *limb = pallas::Base::from(u64::from_le_bytes(bytes));
    }
    let [chain_0, chain_1, chain_2, chain_3] = limbs;
    Anchor::from_base(crypto::poseidon::hash([
        pallas::Base::from(0x5248_4f4d_5354_4154u64), // "RHOMSTAT"
        pallas::Base::from(u64::from(STATE_COMMITMENT_VERSION)),
        chain_0,
        chain_1,
        chain_2,
        chain_3,
        pallas::Base::from(u64::from(height)),
        *commitment_root.inner(),
        pallas::Base::from(commitment_count),
        *nullifier_root.inner(),
        pallas::Base::from(nullifier_count),
    ]))
}

#[cfg(test)]
mod tests {
    use crypto::pallas;

    use super::*;

    fn a(value: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(value))
    }

    #[test]
    fn state_root_binds_network_height_roots_and_counts() {
        let chain = [7; 32];
        let root = state_root(&chain, 5, a(1), 6, a(2), 7);
        assert_ne!(root, state_root(&[8; 32], 5, a(1), 6, a(2), 7));
        assert_ne!(root, state_root(&chain, 6, a(1), 6, a(2), 7));
        assert_ne!(root, state_root(&chain, 5, a(3), 6, a(2), 7));
        assert_ne!(root, state_root(&chain, 5, a(1), 8, a(2), 7));
        assert_ne!(root, state_root(&chain, 5, a(1), 6, a(3), 7));
        assert_ne!(root, state_root(&chain, 5, a(1), 6, a(2), 9));
    }
}
