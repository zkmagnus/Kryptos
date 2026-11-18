//! A wallet's key material, derived from its spending key.

use crypto::diversifier::DiversifierIndex;
use crypto::encryption::{ReceiverKey, TransmissionKey};
use crypto::hash::{blake2b_short, PIN};
use crypto::keys::{Diversifier, FullViewingKey, IncomingViewingKey, NullifierKey, SpendingKey};
use protocol::address::RhombusAddress;
use protocol::coin::Coin;

use crate::{Error, Result};

/// Maximum number of per-address keys in one wallet scan context. The legacy
/// key is additional. Oversized ranges are rejected, never truncated.
pub const MAX_SCAN_ADDRESSES: u64 = 4096;

struct ScanCandidate {
    receiver_key: ReceiverKey,
    diversifier: Option<Diversifier>,
}

/// Receiver keys for an explicit half-open range of new address indices,
/// together with the legacy key that receives all old diversified addresses.
/// Construct once and reuse across blocks; every action tries every key.
pub struct ScanKeys {
    candidates: Vec<ScanCandidate>,
    fingerprint: [u8; 32],
    start: u64,
    end: u64,
}

impl ScanKeys {
    /// Derives the legacy key and every per-address key in `start..end`.
    /// An empty range still scans all legacy addresses.
    ///
    /// # Errors
    /// Rejects reversed ranges or more than [`MAX_SCAN_ADDRESSES`] new keys,
    /// and propagates diversifier derivation errors.
    pub fn new(keys: &WalletKeys, start: u64, end: u64) -> Result<Self> {
        let count = end
            .checked_sub(start)
            .filter(|count| *count <= MAX_SCAN_ADDRESSES)
            .ok_or(crypto::Error::InvalidDerivation(
                "scan range must be ascending and contain at most 4096 addresses",
            ))?;
        let mut candidates = Vec::with_capacity(count as usize + 1);
        candidates.push(ScanCandidate {
            receiver_key: keys.fvk.receiver_key().0,
            diversifier: None,
        });
        let dk = keys.fvk.diversifier_key();
        for index in start..end {
            let diversifier = dk.diversifier(DiversifierIndex::from(index))?;
            candidates.push(ScanCandidate {
                receiver_key: keys.fvk.receiver_key_for_diversifier(&diversifier).0,
                diversifier: Some(diversifier),
            });
        }
        Ok(Self {
            candidates,
            fingerprint: keys.fingerprint(),
            start,
            end,
        })
    }

    /// First per-address index covered by this context, inclusive.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// End of the covered per-address range, exclusive.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Number of attempted keys per output, including the legacy key.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn check_wallet(&self, keys: &WalletKeys) -> Result<()> {
        if self.fingerprint == keys.fingerprint() {
            Ok(())
        } else {
            Err(Error::WrongWallet)
        }
    }

    /// A match never shortens the candidate loop. The supplied operation must
    /// authenticate/reconstruct the commitment before returning a coin.
    pub(crate) fn trial_decrypt(
        &self,
        mut decrypt: impl FnMut(&ReceiverKey) -> protocol::Result<Coin>,
    ) -> Option<(Coin, bool)> {
        let mut found = None;
        for candidate in &self.candidates {
            let decrypted = decrypt(&candidate.receiver_key);
            if let Ok(coin) = decrypted {
                if candidate
                    .diversifier
                    .as_ref()
                    .is_none_or(|expected| expected == coin.diversifier())
                {
                    found = Some((coin, candidate.diversifier.is_none()));
                }
            }
        }
        found
    }
}

impl core::fmt::Debug for ScanKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ScanKeys(<redacted>)")
    }
}

/// The keys a wallet uses, derived once.
pub struct WalletKeys {
    spending: SpendingKey,
    fvk: FullViewingKey,
    ivk: IncomingViewingKey,
    receiver_key: ReceiverKey,
    transmission_key: TransmissionKey,
    legacy_default: bool,
}

impl WalletKeys {
    /// Every key, from the spending key.
    ///
    /// # Errors
    /// Fails if a derived key is degenerate.
    pub fn from_spending_key(sk: SpendingKey) -> Result<Self> {
        let fvk = FullViewingKey::derive(&sk)?;
        let ivk = fvk.incoming_viewing_key()?;
        let (receiver_key, transmission_key) = fvk.receiver_key();
        Ok(Self {
            spending: sk,
            fvk,
            ivk,
            receiver_key,
            transmission_key,
            legacy_default: false,
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
        blake2b_short(PIN, &[&self.fvk.to_bytes()])
    }

    /// The incoming viewing key, for trial decryption.
    pub fn incoming_viewing_key(&self) -> &IncomingViewingKey {
        &self.ivk
    }

    /// Legacy ML-KEM decapsulation key for old addresses. Use [`ScanKeys`]
    /// to include new per-address receiver keys.
    pub fn receiver_key(&self) -> &ReceiverKey {
        &self.receiver_key
    }

    /// Legacy public ML-KEM key shared by this wallet's old addresses.
    pub fn transmission_key(&self) -> &TransmissionKey {
        &self.transmission_key
    }

    /// The address at a diversifier index.
    ///
    /// # Errors
    /// Fails if the index yields an invalid diversifier.
    pub fn address(&self, index: DiversifierIndex) -> Result<RhombusAddress> {
        Ok(RhombusAddress::from_index(&self.fvk, index)?)
    }

    /// Reconstructs an old address with the shared ML-KEM key. New issuance
    /// should use [`Self::address`]; this method preserves existing addresses.
    ///
    /// # Errors
    /// Fails if the index yields an invalid diversifier.
    pub fn legacy_address(&self, index: DiversifierIndex) -> Result<RhombusAddress> {
        Ok(RhombusAddress::from_index_with_kem(
            &self.fvk,
            index,
            &self.transmission_key,
        )?)
    }

    /// Reconstructs the actual address that received a coin, using the scheme
    /// recorded by scanning rather than guessing from its diversifier.
    ///
    /// # Errors
    /// Rejects a coin whose recipient transmission key does not match ours.
    pub fn address_for_coin(&self, coin: &Coin, legacy: bool) -> Result<RhombusAddress> {
        let address = if legacy {
            RhombusAddress::legacy_derive(&self.fvk, *coin.diversifier())?
        } else {
            RhombusAddress::derive(&self.fvk, *coin.diversifier())?
        };
        if address.pk_d() != coin.pk_d() {
            return Err(Error::WrongWallet);
        }
        Ok(address)
    }

    /// The address at index zero.
    ///
    /// # Errors
    /// See [`Self::address`].
    pub fn default_address(&self) -> Result<RhombusAddress> {
        if self.legacy_default {
            self.legacy_address(DiversifierIndex::ZERO)
        } else {
            self.address(DiversifierIndex::ZERO)
        }
    }

    /// Retains the previously issued default/change address after migration.
    pub(crate) fn set_legacy_default(&mut self) {
        self.legacy_default = true;
    }

    /// The diversifier index `address` was derived from, if it is one
    /// of ours.
    pub fn index_of(&self, address: &RhombusAddress) -> Option<DiversifierIndex> {
        self.fvk
            .diversifier_key()
            .index(address.diversifier())
            .ok()
            .filter(|index| {
                self.address(*index).is_ok_and(|ours| &ours == address)
                    || self
                        .legacy_address(*index)
                        .is_ok_and(|ours| &ours == address)
            })
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
        assert_ne!(
            keys.default_address().unwrap().kem_key(),
            keys.address(DiversifierIndex::from(1)).unwrap().kem_key()
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
        assert_eq!(
            keys.index_of(&keys.legacy_address(index).unwrap()),
            Some(index)
        );
        assert_eq!(keys.index_of(&other.default_address().unwrap()), None);
        let ours = keys.address(index).unwrap();
        let swapped_key = RhombusAddress::from_parts(
            *ours.diversifier(),
            *ours.pk_d(),
            other.default_address().unwrap().kem_key().clone(),
        );
        assert_eq!(keys.index_of(&swapped_key), None);
    }

    #[test]
    fn migration_preserves_default_but_new_addresses_use_separate_keys() {
        let mut keys = WalletKeys::from_spending_key(SpendingKey::from_bytes([83; 32])).unwrap();
        let legacy = keys.legacy_address(DiversifierIndex::ZERO).unwrap();
        assert_ne!(keys.default_address().unwrap(), legacy);
        keys.set_legacy_default();
        assert_eq!(keys.default_address().unwrap(), legacy);
        assert_ne!(keys.address(DiversifierIndex::ZERO).unwrap(), legacy);
        assert_ne!(
            keys.address(DiversifierIndex::from(1)).unwrap().kem_key(),
            legacy.kem_key()
        );
    }

    #[test]
    fn scan_ranges_are_explicit_bounded_and_bound_to_the_wallet() {
        let keys = WalletKeys::from_spending_key(SpendingKey::from_bytes([84; 32])).unwrap();
        let other = WalletKeys::from_spending_key(SpendingKey::from_bytes([85; 32])).unwrap();
        assert!(ScanKeys::new(&keys, 2, 1).is_err());
        assert!(ScanKeys::new(&keys, 0, MAX_SCAN_ADDRESSES + 1).is_err());
        assert!(ScanKeys::new(&keys, 0, u64::MAX).is_err());
        let legacy_only = ScanKeys::new(&keys, u64::MAX, u64::MAX).unwrap();
        assert_eq!(legacy_only.candidate_count(), 1);
        let scan = ScanKeys::new(&keys, 42, 44).unwrap();
        assert_eq!(
            (scan.start(), scan.end(), scan.candidate_count()),
            (42, 44, 3)
        );
        assert!(scan.check_wallet(&keys).is_ok());
        assert!(matches!(scan.check_wallet(&other), Err(Error::WrongWallet)));
        assert_eq!(format!("{scan:?}"), "ScanKeys(<redacted>)");
    }
}
