//! BIP 39 seed phrases on top of the ZIP 32 style derivation.
//!
//! A phrase is 24 English words carrying 256 bits of entropy. The BIP 39
//! seed is derived from it with the standard empty BIP 39 passphrase, and the account
//! spending key is `m / 32' / 1' / account'` of that seed as in
//! [`crypto::rip1`]. The phrase is the backup: anyone holding it
//! holds every account.

use bip39::{Language, Mnemonic};
use crypto::keys::SpendingKey;
use crypto::rip1::ExtendedSpendingKey;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Words in a generated phrase.
pub const WORD_COUNT: usize = 24;
/// The only language phrases are generated in; parsing accepts it only,
/// so a phrase written down is unambiguous.
const LANGUAGE: Language = Language::English;
/// BIP 39 passphrase used for KRYPTOS seed derivation.
const SEED_PASSPHRASE: &str = "";

/// A validated seed phrase.
#[derive(Clone)]
pub struct SeedPhrase(Mnemonic);

impl core::fmt::Debug for SeedPhrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SeedPhrase(<secret>)")
    }
}

impl SeedPhrase {
    /// A fresh 24-word phrase.
    ///
    /// # Errors
    /// Cannot fail for the fixed word count; the signature allows the
    /// library's error type to change.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        Mnemonic::generate_in_with(rng, LANGUAGE, WORD_COUNT)
            .map(Self)
            .map_err(|e| Error::SeedPhrase(e.to_string()))
    }

    /// Parses a phrase, ignoring case and surrounding or repeated
    /// whitespace, and checking the checksum.
    ///
    /// # Errors
    /// Returns [`Error::SeedPhrase`] for anything but a valid English
    /// mnemonic of 12 to 24 words.
    pub fn parse(text: &str) -> Result<Self> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            text.split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" "),
        );
        Mnemonic::parse_in(LANGUAGE, normalized.as_str())
            .map(Self)
            .map_err(|e| Error::SeedPhrase(e.to_string()))
    }

    /// The words, space separated.
    pub fn words(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.words().collect::<Vec<_>>().join(" "))
    }

    /// The spending key of `account`.
    ///
    /// # Errors
    /// Returns a derivation error if `account` is not below `2^31`.
    pub fn spending_key(&self, account: u32) -> Result<SpendingKey> {
        let seed = Zeroizing::new(self.0.to_seed(SEED_PASSPHRASE));
        Ok(ExtendedSpendingKey::account(seed.as_ref(), account)?
            .spending_key()
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use crypto::encoding::to_hex;
    use crypto::rip1::ChildIndex;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::WalletKeys;

    /// The BIP 39 test vector for all-zero entropy.
    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    #[test]
    fn generated_phrases_round_trip_and_differ() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let a = SeedPhrase::generate(&mut rng).unwrap();
        let b = SeedPhrase::generate(&mut rng).unwrap();
        assert_eq!(a.words().split(' ').count(), WORD_COUNT);
        assert_ne!(*a.words(), *b.words());
        let parsed = SeedPhrase::parse(&a.words()).unwrap();
        assert_eq!(
            parsed.spending_key(0).unwrap().to_bytes(),
            a.spending_key(0).unwrap().to_bytes()
        );
        assert_eq!(format!("{a:?}"), "SeedPhrase(<secret>)");
    }

    #[test]
    fn parsing_normalizes_and_checks_the_checksum() {
        let shouted = format!("  {}  ", ZERO_PHRASE.to_uppercase().replace(' ', "\n "));
        assert_eq!(*SeedPhrase::parse(&shouted).unwrap().words(), ZERO_PHRASE);
        let wrong_checksum = ZERO_PHRASE.replace("art", "abandon");
        assert!(matches!(
            SeedPhrase::parse(&wrong_checksum),
            Err(Error::SeedPhrase(_))
        ));
        assert!(SeedPhrase::parse("").is_err());
        assert!(SeedPhrase::parse("not words at all").is_err());
    }

    #[test]
    fn derivation_is_pinned_and_accounts_differ() {
        let phrase = SeedPhrase::parse(ZERO_PHRASE).unwrap();
        let sk0 = phrase.spending_key(0).unwrap();
        let sk1 = phrase.spending_key(1).unwrap();
        assert_ne!(sk0.to_bytes(), sk1.to_bytes());
        assert!(phrase.spending_key(1 << 31).is_err());
        // Independently checked with Python hashlib; see
        // docs/seed-derivation-compatibility.md and scripts/check_seed_vectors.py.
        // Keep production derivation stable so existing wallets retain keys.
        assert_eq!(
            to_hex(&sk0.to_bytes()),
            "88cffd3a1ae06fdcc3096cfdd5d488961565de3fbc9d981117ba84edecd4863a",
            "account 0 spending key of the all-zero phrase changed"
        );
        assert_eq!(
            to_hex(&sk1.to_bytes()),
            "7736bcda73926421570caa1d2375dc2d71ddc33c32194be23d78f80658274f84",
            "account 1 spending key of the all-zero phrase changed"
        );
        let keys = WalletKeys::from_spending_key(sk0).unwrap();
        let address = keys.default_address().unwrap();
        let encoded = address.encode(protocol::address::Network::Main);
        assert_eq!(
            protocol::address::KryptosAddress::decode(
                &encoded,
                protocol::address::Network::Main
            ),
            Ok(address),
            "account 0 address of the all-zero phrase did not round-trip"
        );
    }

    #[test]
    fn bip39_reference_and_intermediate_derivation_stages_are_pinned() {
        let phrase = SeedPhrase::parse(ZERO_PHRASE).unwrap();
        // Official BIP39 all-zero 256-bit entropy vector. TREZOR is only
        // the reference passphrase; Kryptos production uses the empty one.
        assert_eq!(
            to_hex(&phrase.0.to_seed("TREZOR")),
            concat!(
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af",
                "7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
            )
        );
        let seed = phrase.0.to_seed(SEED_PASSPHRASE);
        assert_eq!(
            to_hex(&seed),
            concat!(
                "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c",
                "6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
            )
        );
        let master = ExtendedSpendingKey::master(&seed).unwrap();
        assert_eq!(
            to_hex(&master.spending_key().to_bytes()),
            "939edc84b8082c372f6946ba2ba426a3643f557279559b3948b630c6c38d26b3"
        );
        let purpose = master.child(ChildIndex::hardened(32).unwrap()).unwrap();
        assert_eq!(
            to_hex(&purpose.spending_key().to_bytes()),
            "6c7f416029f7af9a825c7708d0104dbcba1bd90389672eb25fbfa12b82a6a48f"
        );
        let coin_type = purpose.child(ChildIndex::hardened(1).unwrap()).unwrap();
        assert_eq!(
            to_hex(&coin_type.spending_key().to_bytes()),
            "998868c0baa59b676dde0d0dfbdb0d39663d3ec9a7ea51c96625fceef11d2f75"
        );
    }
}
