//! Key agreement and authenticated encryption for coin ciphertexts.
//!
//! ```text
//! sender:    esk random,  epk = [esk] g_d,  shared = [esk] pk_d
//! receiver:  shared = [ivk] epk
//! key       = KDF(shared, epk)
//! ct        = ChaCha20-Poly1305(key, nonce = 0, pt)
//! ```
//!
//! The nonce is zero because every key is used exactly once.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::curve::is_identity;
use crate::encoding::{point_from_bytes, point_to_bytes, Encoded};
use crate::hash::{blake2b_short, COIN_KDF, SHORT_OUTPUT_LEN};
use crate::keys::{DiversifiedTransmissionKey, IncomingViewingKey};
use crate::secret::SecretScalar;
use crate::{Error, Result};

/// Byte length of an ML-KEM-768 encapsulation key.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1184;
/// Byte length of the seed pair (`d || z`) used by deterministic ML-KEM keygen.
pub const KEM_SEED_LEN: usize = 64;
/// Byte length of an ML-KEM-768 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
/// Byte length of the ML-KEM shared secret.
pub const KEM_SHARED_SECRET_LEN: usize = 32;

/// Receiver's ML-KEM decapsulation key. It can read incoming coins but
/// does not grant spend authority.
pub struct ReceiverKey(ml_kem::kem::DecapsulationKey<MlKem768Params>);

/// Public ML-KEM encapsulation key placed in a payment address.
#[derive(Clone)]
pub struct TransmissionKey(ml_kem::kem::EncapsulationKey<MlKem768Params>);

/// Encapsulation sent to a receiver to establish a shared secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KemCiphertext(Ciphertext<MlKem768>);

/// Shared secret established by ML-KEM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret([u8; KEM_SHARED_SECRET_LEN]);

impl ReceiverKey {
    /// Deterministically derives the ML-KEM-768 key pair from `d || z`.
    pub fn from_seed(seed: &[u8; KEM_SEED_LEN]) -> (Self, TransmissionKey) {
        let (d, z) = seed.split_at(KEM_SEED_LEN / 2);
        let d = ml_kem::B32::try_from(d).unwrap_or_default();
        let z = ml_kem::B32::try_from(z).unwrap_or_default();
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        (Self(dk), TransmissionKey(ek))
    }

    /// Decapsulates an ML-KEM ciphertext.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> Result<KemSharedSecret> {
        let shared = self
            .0
            .decapsulate(&ciphertext.0)
            .map_err(|_| Error::DecryptionFailed)?;
        let mut bytes = [0u8; KEM_SHARED_SECRET_LEN];
        bytes.copy_from_slice(shared.as_slice());
        Ok(KemSharedSecret(bytes))
    }
}

impl TransmissionKey {
    /// Canonical FIPS 203 encoding of the encapsulation key.
    pub fn to_bytes(&self) -> [u8; KEM_ENCAPSULATION_KEY_LEN] {
        let encoded = self.0.as_bytes();
        let mut bytes = [0u8; KEM_ENCAPSULATION_KEY_LEN];
        bytes.copy_from_slice(encoded.as_slice());
        bytes
    }

    /// Parses an encapsulation key from its fixed-size FIPS 203 encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; KEM_ENCAPSULATION_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidDerivation("ML-KEM encapsulation key length"))?;
        // ML-KEM-768 encodes three 256-coefficient polynomials in the first
        // 1152 bytes, with each coefficient represented as an unsigned 12-bit
        // integer. FIPS 203 requires every decoded coefficient to be < q.
        if bytes[..KEM_ENCAPSULATION_KEY_LEN - KEM_SHARED_SECRET_LEN]
            .chunks_exact(3)
            .any(|chunk| {
                let c0 = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
                let c1 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
                c0 >= 3329 || c1 >= 3329
            })
        {
            return Err(Error::InvalidDerivation(
                "non-canonical ML-KEM encapsulation key",
            ));
        }
        Ok(Self(
            ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(bytes.into()),
        ))
    }

    /// Encapsulates a fresh shared secret to this key.
    pub fn encapsulate(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(KemCiphertext, KemSharedSecret)> {
        let (ciphertext, shared) = self.0.encapsulate(rng).map_err(|_| Error::DegenerateKey)?;
        let mut bytes = [0u8; KEM_SHARED_SECRET_LEN];
        bytes.copy_from_slice(shared.as_slice());
        Ok((KemCiphertext(ciphertext), KemSharedSecret(bytes)))
    }
}

impl KemCiphertext {
    /// Canonical ML-KEM ciphertext encoding.
    pub fn to_bytes(&self) -> [u8; KEM_CIPHERTEXT_LEN] {
        let mut bytes = [0u8; KEM_CIPHERTEXT_LEN];
        bytes.copy_from_slice(self.0.as_slice());
        bytes
    }

    /// Decodes an ML-KEM ciphertext of the required fixed length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ciphertext = Ciphertext::<MlKem768>::try_from(bytes)
            .map_err(|_| Error::InvalidDerivation("ML-KEM ciphertext length"))?;
        Ok(Self(ciphertext))
    }
}

impl KemSharedSecret {
    /// Borrows the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; KEM_SHARED_SECRET_LEN] {
        &self.0
    }

    /// Derives the coin encryption key, binding the KEM ciphertext and coin
    /// commitment into the KDF.
    pub fn coin_key(&self, ciphertext: &KemCiphertext, cmx: &[u8; 32]) -> SymmetricKey {
        SymmetricKey(blake2b_short(
            COIN_KDF,
            &[&self.0, &ciphertext.to_bytes(), cmx],
        ))
    }
}

impl core::fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemCiphertext(..)")
    }
}

impl core::fmt::Debug for KemSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSharedSecret(<redacted>)")
    }
}

impl PartialEq for TransmissionKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for TransmissionKey {}

impl core::fmt::Debug for TransmissionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransmissionKey(..)")
    }
}

impl core::fmt::Debug for ReceiverKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReceiverKey(<redacted>)")
    }
}

#[cfg(test)]
mod ml_kem_tests {
    use super::*;

    #[test]
    fn encapsulation_key_encoding_must_have_canonical_coefficients() {
        let (_, key) = ReceiverKey::from_seed(&[7; KEM_SEED_LEN]);
        assert_eq!(TransmissionKey::from_bytes(&key.to_bytes()).unwrap(), key);

        // Encode coefficient q=3329 in the first 12-bit slot.
        let mut noncanonical = key.to_bytes();
        noncanonical[0] = 3329u16 as u8;
        noncanonical[1] = (noncanonical[1] & 0xf0) | ((3329u16 >> 8) as u8);
        assert!(TransmissionKey::from_bytes(&noncanonical).is_err());
    }
}

/// Byte length of the authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;
/// Byte length of a symmetric key.
pub const SYMMETRIC_KEY_LEN: usize = SHORT_OUTPUT_LEN;

/// `esk`: the sender's ephemeral secret.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSecretKey(SecretScalar);

impl EphemeralSecretKey {
    /// Wraps a scalar, normally derived from the coin's random seed.
    pub fn from_scalar(scalar: pallas::Scalar) -> Self {
        Self(SecretScalar::new(scalar))
    }

    /// Samples a fresh secret, for tests and dummy outputs.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_scalar(pallas::Scalar::random(rng))
    }

    /// Canonical encoding of the ephemeral secret scalar.
    pub fn to_bytes(&self) -> Encoded {
        crate::encoding::scalar_to_bytes(&self.0.expose())
    }

    /// Decodes a canonical scalar.
    ///
    /// # Errors
    /// Returns [`Error::InvalidScalar`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        crate::encoding::scalar_from_bytes(bytes).map(Self::from_scalar)
    }

    /// `epk = [esk] g_d`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn public_key(&self, g_d: &pallas::Point) -> EphemeralPublicKey {
        EphemeralPublicKey(g_d * self.0.expose())
    }

    /// `shared = [esk] pk_d`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn agree(&self, pk_d: &DiversifiedTransmissionKey) -> SharedSecret {
        SharedSecret(pk_d.as_point() * self.0.expose())
    }
}

/// `epk`: the public half of the ephemeral key, sent in the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EphemeralPublicKey(pallas::Point);

impl EphemeralPublicKey {
    /// `shared = [ivk] epk`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn agree(&self, ivk: &IncomingViewingKey) -> SharedSecret {
        SharedSecret(self.0 * ivk.expose())
    }

    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        point_to_bytes(&self.0)
    }

    /// Decodes a compressed point, rejecting the identity.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPoint`] on a non-canonical encoding and
    /// [`Error::DegenerateKey`] for the identity.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        let point = point_from_bytes(bytes)?;
        if is_identity(&point) {
            return Err(Error::DegenerateKey);
        }
        Ok(Self(point))
    }
}

/// The Diffie-Hellman shared secret between sender and receiver.
pub struct SharedSecret(pallas::Point);

impl SharedSecret {
    /// Derives the symmetric coin encryption key.
    pub fn kdf(&self, epk: &EphemeralPublicKey) -> SymmetricKey {
        SymmetricKey(blake2b_short(
            COIN_KDF,
            &[&point_to_bytes(&self.0), &epk.to_bytes()],
        ))
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// A single-use symmetric key for ChaCha20-Poly1305.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LEN]);

impl SymmetricKey {
    /// Samples a random symmetric key.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; SYMMETRIC_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }

    /// Encrypts `plaintext`. The output is `plaintext.len() + TAG_LEN` bytes.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Encryption only fails when the plaintext exceeds 2^38 bytes.
        self.cipher()
            .encrypt(&zero_nonce(), plaintext)
            .unwrap_or_default()
    }

    /// Decrypts and authenticates `ciphertext`.
    ///
    /// # Errors
    /// Returns [`Error::DecryptionFailed`] if the tag does not match.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(&zero_nonce(), ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Decrypts a leading fragment of a ciphertext without the
    /// authentication tag, for compact-block detection.
    ///
    /// The AEAD reserves the first `ChaCha20` block for the Poly1305 key
    /// and encrypts the plaintext from block one, so this seeks to byte 64
    /// of the keystream before `XOR`ing. The caller must confirm the coin
    /// against its commitment, since nothing here is authenticated.
    #[must_use]
    pub fn decrypt_lead(&self, lead: &[u8]) -> Vec<u8> {
        let mut cipher = ChaCha20::new(Key::from_slice(&self.0), &Nonce::default());
        // Byte 64 is the start of block one; block zero is the MAC key.
        cipher.seek(64u32);
        let mut out = lead.to_vec();
        cipher.apply_keystream(&mut out);
        out
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

fn zero_nonce() -> Nonce {
    Nonce::default()
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::{Diversifier, FullViewingKey, SpendingKey};

    struct Receiver {
        ivk: IncomingViewingKey,
        g_d: pallas::Point,
        pk_d: DiversifiedTransmissionKey,
    }

    fn receiver(seed: u64) -> Receiver {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ivk = FullViewingKey::derive(&SpendingKey::random(&mut rng))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        let d = Diversifier::random(&mut rng);
        Receiver {
            g_d: d.base().unwrap(),
            pk_d: ivk.transmission_key(&d).unwrap(),
            ivk,
        }
    }

    #[test]
    fn sender_and_receiver_derive_the_same_key() {
        let r = receiver(1);
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(2));
        let epk = esk.public_key(&r.g_d);
        let sender_key = esk.agree(&r.pk_d).kdf(&epk);
        let receiver_key = epk.agree(&r.ivk).kdf(&epk);
        assert_eq!(sender_key.0, receiver_key.0);
    }

    #[test]
    fn wrong_receiver_derives_a_different_key() {
        let (a, b) = (receiver(3), receiver(4));
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(5));
        let epk = esk.public_key(&a.g_d);
        assert_ne!(
            esk.agree(&a.pk_d).kdf(&epk).0,
            epk.agree(&b.ivk).kdf(&epk).0
        );
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips_and_detects_tampering() {
        let key = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(6));
        let ct = key.encrypt(b"hello");
        assert_eq!(ct.len(), 5 + TAG_LEN);
        assert_eq!(key.decrypt(&ct), Ok(b"hello".to_vec()));

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_eq!(key.decrypt(&tampered), Err(Error::DecryptionFailed));

        let other = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(7));
        assert_eq!(other.decrypt(&ct), Err(Error::DecryptionFailed));
    }

    #[test]
    fn decrypt_lead_matches_the_aead_on_the_leading_bytes() {
        let key = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(20));
        let plaintext: Vec<u8> = (0u8..80).collect();
        let ciphertext = key.encrypt(&plaintext);
        for lead in [0usize, 1, 52, 80] {
            let recovered = key.decrypt_lead(&ciphertext[..lead]);
            assert_eq!(recovered, &plaintext[..lead], "lead {lead}");
        }
    }

    #[test]
    fn ephemeral_keys_roundtrip_bytes_and_reject_identity() {
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(8));
        assert_eq!(
            EphemeralSecretKey::from_bytes(&esk.to_bytes())
                .unwrap()
                .to_bytes(),
            esk.to_bytes()
        );
        let epk = esk.public_key(&receiver(9).g_d);
        assert_eq!(EphemeralPublicKey::from_bytes(&epk.to_bytes()), Ok(epk));
        let identity = point_to_bytes(&pallas::Point::identity());
        assert_eq!(
            EphemeralPublicKey::from_bytes(&identity),
            Err(Error::DegenerateKey)
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(10));
        let shared = esk.agree(&receiver(11).pk_d);
        assert_eq!(format!("{shared:?}"), "SharedSecret(<redacted>)");
        assert_eq!(
            format!("{:?}", shared.kdf(&esk.public_key(&receiver(11).g_d))),
            "SymmetricKey(<redacted>)"
        );
    }
}
