//! A wallet's key material, derived from its spending key.

use crypto::diversifier::DiversifierIndex;
use crypto::encryption::{ReceiverKey, TransmissionKey};
use crypto::hash::{blake2b_short, PIN};
use crypto::keys::{
    FullViewingKey, IncomingViewingKey, NullifierKey, OutgoingViewingKey, SpendingKey,
};
use protocol::address::RhombusAddress;

use crate::Result;

/// The keys a wallet uses, derived once.
pub struct WalletKeys {
    spending: SpendingKey,
    fvk: FullViewingKey,
    ivk: IncomingViewingKey,
    ovk: OutgoingViewingKey,
    receiver_key: ReceiverKey,
    transmission_key: TransmissionKey,
}

impl WalletKeys {
    /// Every key, from the spending key.
    ///
    /// # Errors
    /// Fails if a derived key is degenerate.
    pub fn from_spending_key(sk: SpendingKey) -> Result<Self> {
        let fvk = FullViewingKey::derive(&sk)?;
        let ivk = fvk.incoming_viewing_key()?;
        let ovk = fvk.outgoing_viewing_key();
        let (receiver_key, transmission_key) = fvk.receiver_key();
        Ok(Self {
            spending: sk,
            fvk,
            ivk,
            ovk,
            receiver_key,
            transmission_key,
        })
    }

    /// The spending key.
    pub fn spending_key(&self) -> &SpendingKey {
        &self.spending
    }

    /// The nullifier key used to track spent notes.
    pub fn nullifier_key(&self) -> &NullifierKey {
        self.fvk.nk()
    }

    /// Stable identifier used to bind wallet state to its derived keys.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        blake2b_short(PIN, &[&self.fvk.ak().to_bytes(), self.ovk.as_bytes()])
    }

    /// The incoming viewing key, for trial decryption.
    pub fn incoming_viewing_key(&self) -> &IncomingViewingKey {
        &self.ivk
    }

    /// The outgoing viewing key, for recovering what was sent.
    pub fn outgoing_viewing_key(&self) -> &OutgoingViewingKey {
        &self.ovk
    }

    /// ML-KEM decapsulation key for incoming note scanning.
    pub fn receiver_key(&self) -> &ReceiverKey {
        &self.receiver_key
    }

    /// Public ML-KEM key shared by this wallet's diversified addresses.
    pub fn transmission_key(&self) -> &TransmissionKey {
        &self.transmission_key
    }

    /// The address at a diversifier index.
    ///
    /// # Errors
    /// Fails if the index yields an invalid diversifier.
    pub fn address(&self, index: DiversifierIndex) -> Result<RhombusAddress> {
        Ok(RhombusAddress::from_index_with_kem(
            &self.fvk,
            index,
            &self.transmission_key,
        )?)
    }

    /// The address at index zero.
    ///
    /// # Errors
    /// See [`Self::address`].
    pub fn default_address(&self) -> Result<RhombusAddress> {
        self.address(DiversifierIndex::ZERO)
    }

    /// The diversifier index `address` was derived from, if it is one
    /// of ours.
    pub fn index_of(&self, address: &RhombusAddress) -> Option<DiversifierIndex> {
        self.fvk
            .diversifier_key()
            .index(address.diversifier())
            .ok()
            .filter(|index| self.address(*index).is_ok_and(|ours| &ours == address))
    }
}

impl core::fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WalletKeys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn keys_derive_consistent_addresses() {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1));
        let keys = WalletKeys::from_spending_key(sk.clone()).unwrap();
        let again = WalletKeys::from_spending_key(sk).unwrap();
        assert_eq!(
            keys.default_address().unwrap(),
            again.default_address().unwrap()
        );
        assert_ne!(
            keys.default_address().unwrap(),
            keys.address(DiversifierIndex::from(1)).unwrap()
        );
        assert_eq!(format!("{keys:?}"), "WalletKeys(<redacted>)");
    }

    #[test]
    fn our_addresses_map_back_to_their_index() {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(3)))
                .unwrap();
        let other =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(4)))
                .unwrap();
        let index = DiversifierIndex::from(42);
        assert_eq!(keys.index_of(&keys.address(index).unwrap()), Some(index));
        assert_eq!(keys.index_of(&other.default_address().unwrap()), None);
    }
}
