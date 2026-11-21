//! A wallet's key material, derived from its spending key.

use crypto::diversifier::DiversifierIndex;
use crypto::encryption::ReceiverKey;
use crypto::hash::{blake2b_short, PIN};
use crypto::keys::{FullViewingKey, IncomingViewingKey, NullifierKey, SpendingKey};
use protocol::address::KryptosAddress;
use protocol::coin::Coin;
use protocol::encryption::PreparedIvk;

use crate::{Error, Result};

/// Maximum number of per-address keys in one wallet scan context.
/// Oversized ranges are rejected, never truncated.
pub const MAX_SCAN_ADDRESSES: u64 = 4096;

struct ScanCandidate {
    birthday_height: u32,
    receiver_key: ReceiverKey,
    ivk: PreparedIvk,
}

/// Receiver keys for an explicit half-open range of address indices.
/// Construct once and reuse across blocks; each action tries the keys whose
/// birthdays have been reached.
pub struct ScanKeys {
    candidates: Vec<ScanCandidate>,
    fingerprint: [u8; 32],
    start: u64,
    end: u64,
}

impl ScanKeys {
    /// Derives every per-address key in `start..end`.
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
        let mut candidates = Vec::with_capacity(count as usize);
        let dk = keys.fvk.diversifier_key();
        for index in start..end {
            let diversifier = dk.diversifier(DiversifierIndex::from(index))?;
            candidates.push(ScanCandidate {
                birthday_height: 0,
                receiver_key: keys.fvk.receiver_key_for_diversifier(&diversifier).0,
                ivk: PreparedIvk::new(keys.incoming_viewing_key(), diversifier)?,
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

    /// Number of keys in the configured range.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn set_birthdays(&mut self, birthdays: &[u32]) {
        for (candidate, height) in self.candidates.iter_mut().zip(birthdays) {
            candidate.birthday_height = *height;
        }
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
        height: u32,
        mut decrypt: impl FnMut(&PreparedIvk, &ReceiverKey) -> protocol::Result<Coin>,
    ) -> Option<(Coin, bool)> {
        let mut found = None;
        for candidate in &self.candidates {
            if height < candidate.birthday_height {
                continue;
            }
            if let Ok(coin) = decrypt(&candidate.ivk, &candidate.receiver_key) {
                found = Some((coin, false));
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
}

impl WalletKeys {
    /// Every key, from the spending key.
    ///
    /// # Errors
    /// Fails if a derived key is degenerate.
    pub fn from_spending_key(sk: SpendingKey) -> Result<Self> {
        let fvk = FullViewingKey::derive(&sk)?;
        let ivk = fvk.incoming_viewing_key()?;
        Ok(Self {
            spending: sk,
            fvk,
            ivk,
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

    /// The address at a diversifier index.
    ///
    /// # Errors
    /// Fails if the index yields an invalid diversifier.
    pub fn address(&self, index: DiversifierIndex) -> Result<KryptosAddress> {
        Ok(KryptosAddress::from_index(&self.fvk, index)?)
    }

    /// Reconstructs the actual address that received a coin, using the scheme
    /// recorded by scanning rather than guessing from its diversifier.
    ///
    /// # Errors
    /// Rejects a coin whose recipient transmission key does not match ours.
    pub fn address_for_coin(&self, coin: &Coin, legacy: bool) -> Result<KryptosAddress> {
        if legacy {
            return Err(Error::Corrupt("unsupported legacy address scheme"));
        }
        let address = KryptosAddress::derive(&self.fvk, *coin.diversifier())?;
        if address.pk_d() != coin.pk_d() {
            return Err(Error::WrongWallet);
        }
        Ok(address)
    }

    /// The address at index zero.
    ///
    /// # Errors
    /// See [`Self::address`].
    pub fn default_address(&self) -> Result<KryptosAddress> {
        self.address(DiversifierIndex::ZERO)
    }

    /// The diversifier index `address` was derived from, if it is one
    /// of ours.
    pub fn index_of(&self, address: &KryptosAddress) -> Option<DiversifierIndex> {
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
        assert_eq!(keys.index_of(&other.default_address().unwrap()), None);
    }

    #[test]
    fn scan_ranges_are_explicit_bounded_and_bound_to_the_wallet() {
        let keys = WalletKeys::from_spending_key(SpendingKey::from_bytes([84; 32])).unwrap();
        let other = WalletKeys::from_spending_key(SpendingKey::from_bytes([85; 32])).unwrap();
        assert!(ScanKeys::new(&keys, 2, 1).is_err());
        assert!(ScanKeys::new(&keys, 0, MAX_SCAN_ADDRESSES + 1).is_err());
        assert!(ScanKeys::new(&keys, 0, u64::MAX).is_err());
        let empty = ScanKeys::new(&keys, u64::MAX, u64::MAX).unwrap();
        assert_eq!(empty.candidate_count(), 0);
        let scan = ScanKeys::new(&keys, 42, 44).unwrap();
        assert_eq!(
            (scan.start(), scan.end(), scan.candidate_count()),
            (42, 44, 2)
        );
        assert!(scan.check_wallet(&keys).is_ok());
        assert!(matches!(scan.check_wallet(&other), Err(Error::WrongWallet)));
        assert_eq!(format!("{scan:?}"), "ScanKeys(<redacted>)");
    }
}
