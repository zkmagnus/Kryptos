//! Coin plaintext layout, encryption, and trial decryption.
//!
//! ```text
//! coin plaintext  = version(1) || d(11) || value(8 LE) || rseed(32) ||
//! out plaintext   = pk_d(32) || ek(1184) || KEM shared secret(32)
//! ```
//!
//! The receiver decrypts with `ivk`. The sender, or a holder of its `ovk`,
//! decrypts the out ciphertext to recover `esk` and `pk_d` and then the coin.
//! Both paths rebuild the coin and check it against the public commitment
//! and ephemeral key, so a ciphertext can never claim a coin it does not
//! match.

use crypto::commitment::ValueCommitment;
use crypto::encoding::ENCODED_LEN;
use crypto::encryption::{
    KemCiphertext, KemSharedSecret, ReceiverKey, SymmetricKey, TransmissionKey, KEM_CIPHERTEXT_LEN,
    KEM_ENCAPSULATION_KEY_LEN, KEM_SHARED_SECRET_LEN, TAG_LEN,
};
use crypto::keys::{
    DiversifiedTransmissionKey, Diversifier, IncomingViewingKey, OutgoingViewingKey,
    DIVERSIFIER_LEN,
};
use rand_core::{CryptoRng, RngCore};

use crate::amount::RawCoin;
use crate::bytes::{Encodable, Reader, Writer};
use crate::coin::{Coin, ExtractedCoinCommitment, RandomSeed, Rho, RANDOM_SEED_LEN};
use crate::{Error, Result};

/// The only plaintext version currently defined.
const PLAINTEXT_VERSION: u8 = 0x01;

/// Byte length of a coin plaintext.
pub const COIN_PLAINTEXT_LEN: usize = 1 + DIVERSIFIER_LEN + 8 + RANDOM_SEED_LEN;
/// Byte length of a coin ciphertext.
pub const COIN_CIPHERTEXT_LEN: usize = COIN_PLAINTEXT_LEN + TAG_LEN;
/// Byte length of an outgoing plaintext.
pub const OUT_PLAINTEXT_LEN: usize =
    ENCODED_LEN + KEM_ENCAPSULATION_KEY_LEN + KEM_SHARED_SECRET_LEN;
/// Byte length of an outgoing ciphertext.
pub const OUT_CIPHERTEXT_LEN: usize = OUT_PLAINTEXT_LEN + TAG_LEN;
/// Byte length of an encoded [`EncryptedCoin`].
pub const ENCRYPTED_COIN_LEN: usize =
    1 + KEM_CIPHERTEXT_LEN + COIN_CIPHERTEXT_LEN + OUT_CIPHERTEXT_LEN;
/// Bytes of the coin ciphertext a light client needs to detect and
/// rebuild a coin: version, diversifier, value and seed.
pub const COMPACT_COIN_LEAD: usize = 1 + DIVERSIFIER_LEN + 8 + RANDOM_SEED_LEN;

/// The encrypted form of a coin as it appears in an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedCoin {
    kem_ciphertext: KemCiphertext,
    enc_ciphertext: [u8; COIN_CIPHERTEXT_LEN],
    out_ciphertext: [u8; OUT_CIPHERTEXT_LEN],
}

impl EncryptedCoin {
    /// The ML-KEM encapsulation sent to the receiver.
    pub fn kem_ciphertext(&self) -> &KemCiphertext {
        &self.kem_ciphertext
    }

    /// The coin ciphertext.
    pub fn enc_ciphertext(&self) -> &[u8; COIN_CIPHERTEXT_LEN] {
        &self.enc_ciphertext
    }

    /// The outgoing ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_LEN] {
        &self.out_ciphertext
    }

    /// Builds from parts already validated elsewhere.
    pub fn from_parts(
        kem_ciphertext: KemCiphertext,
        enc_ciphertext: [u8; COIN_CIPHERTEXT_LEN],
        out_ciphertext: [u8; OUT_CIPHERTEXT_LEN],
    ) -> Self {
        Self {
            kem_ciphertext,
            enc_ciphertext,
            out_ciphertext,
        }
    }
}

impl Encodable for EncryptedCoin {
    fn write(&self, w: &mut Writer) {
        w.put_u8(2)
            .put(&self.kem_ciphertext.to_bytes())
            .put(&self.enc_ciphertext)
            .put(&self.out_ciphertext);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.take_u8()? != 2 {
            return Err(Error::Malformed("unsupported encrypted-coin version"));
        }
        let kem_ciphertext = KemCiphertext::from_bytes(r.take(KEM_CIPHERTEXT_LEN)?)?;
        Ok(Self::from_parts(
            kem_ciphertext,
            r.take_array()?,
            r.take_array()?,
        ))
    }
}

/// Encrypts `coin` for its recipient and, if `ovk` is given, for the sender.
///
/// `cv` is the action's value commitment, bound into the outgoing key so a
/// sender can only recover outputs of the action it actually created.
///
/// # Errors
/// Fails if the coin's recipient has an invalid diversifier.
pub fn encrypt_coin(
    coin: &Coin,
    ek: &TransmissionKey,
    ovk: Option<&OutgoingViewingKey>,
    cv: &ValueCommitment,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EncryptedCoin> {
    let cmx = coin.cmx()?.to_bytes();
    let (kem_ciphertext, shared_secret) = ek.encapsulate(rng)?;
    let key = shared_secret.coin_key(&kem_ciphertext, &cmx);
    let enc_ciphertext = fixed(key.encrypt(&CoinPlaintext::from_coin(coin).encode()))?;

    let (ock, out_plaintext) = match ovk {
        Some(ovk) => (
            SymmetricKey::outgoing_kem(ovk, &cv.to_bytes(), &cmx, &kem_ciphertext),
            out_plaintext(coin.pk_d(), ek, &shared_secret),
        ),
        None => (SymmetricKey::random(rng), random_out_plaintext(rng)),
    };
    let out_ciphertext = fixed(ock.encrypt(&out_plaintext))?;

    Ok(EncryptedCoin {
        kem_ciphertext,
        enc_ciphertext,
        out_ciphertext,
    })
}
/// Trial-decrypts as the receiver.
///
/// `rho` and `cmx` come from the action carrying the ciphertext.
///
/// # Errors
/// Returns [`crypto::Error::DecryptionFailed`] when the coin is not
/// for this key, or [`Error::CoinDecryption`] if it decrypts but does not
/// match the action.
pub fn decrypt_coin_with_ivk(
    ivk: &IncomingViewingKey,
    receiver_key: &ReceiverKey,
    encrypted: &EncryptedCoin,
    rho: Rho,
    cmx: &ExtractedCoinCommitment,
) -> Result<Coin> {
    let shared_secret = receiver_key.decapsulate(&encrypted.kem_ciphertext)?;
    let key = shared_secret.coin_key(&encrypted.kem_ciphertext, &cmx.to_bytes());
    let plaintext = CoinPlaintext::decode(&key.decrypt(&encrypted.enc_ciphertext)?)?;
    let pk_d = ivk.transmission_key(&plaintext.diversifier)?;
    finish_decryption(plaintext, pk_d, rho, cmx)
}

/// Detects and rebuilds a coin from the leading bytes of its ciphertext,
/// as a light client does over a compact block.
///
/// The lead is decrypted with the receiver's key but not authenticated,
/// so the coin is accepted only once it matches the action's commitment.
///
/// # Errors
/// Returns [`crypto::Error::DecryptionFailed`] when the coin is not
/// for this key, or [`Error::CoinDecryption`] if the lead decrypts but
/// does not match the commitment.
pub fn detect_coin_with_ivk(
    ivk: &IncomingViewingKey,
    receiver_key: &ReceiverKey,
    kem_ciphertext: &KemCiphertext,
    enc_lead: &[u8; COMPACT_COIN_LEAD],
    rho: Rho,
    cmx: &ExtractedCoinCommitment,
) -> Result<Coin> {
    let shared_secret = receiver_key.decapsulate(kem_ciphertext)?;
    let key = shared_secret.coin_key(kem_ciphertext, &cmx.to_bytes());
    let lead = key.decrypt_lead(enc_lead);
    let plaintext = CoinLead::decode(&lead)?;
    let pk_d = ivk.transmission_key(&plaintext.diversifier)?;
    let coin = Coin::new(
        plaintext.diversifier,
        pk_d,
        plaintext.value,
        rho,
        plaintext.rseed,
    );
    if coin.cmx()? != *cmx {
        return Err(Error::CoinDecryption("commitment mismatch"));
    }
    Ok(coin)
}

/// The fields of a coin plaintext.
struct CoinLead {
    diversifier: Diversifier,
    value: RawCoin,
    rseed: RandomSeed,
}

impl CoinLead {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take_u8()? != PLAINTEXT_VERSION {
            return Err(Error::CoinDecryption("unknown plaintext version"));
        }
        let diversifier = Diversifier::from_bytes(r.take_array()?);
        let value = RawCoin::from_raw(r.take_u64_le()?)?;
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        r.finish()?;
        Ok(Self {
            diversifier,
            value,
            rseed,
        })
    }
}

/// Decrypts as the sender, using the outgoing viewing key.
///
/// # Errors
/// Returns [`crypto::Error::DecryptionFailed`] when this key did not
/// send the coin, or [`Error::CoinDecryption`] on an inconsistent plaintext.
pub fn decrypt_coin_with_ovk(
    ovk: &OutgoingViewingKey,
    encrypted: &EncryptedCoin,
    cv: &ValueCommitment,
    rho: Rho,
    cmx: &ExtractedCoinCommitment,
) -> Result<Coin> {
    let (pk_d, _, shared_secret) = recover_output_keys(ovk, encrypted, cv, cmx)?;
    decrypt_coin_with_keys(&pk_d, &shared_secret, encrypted, rho, cmx)
}

/// Recovers, as the sender, the transmission key and KEM shared secret of
/// an output: the two values that let anyone decrypt exactly that coin.
///
/// # Errors
/// Returns [`crypto::Error::DecryptionFailed`] when this key did not
/// send the coin.
pub fn recover_output_keys(
    ovk: &OutgoingViewingKey,
    encrypted: &EncryptedCoin,
    cv: &ValueCommitment,
    cmx: &ExtractedCoinCommitment,
) -> Result<(DiversifiedTransmissionKey, TransmissionKey, KemSharedSecret)> {
    let ock = SymmetricKey::outgoing_kem(
        ovk,
        &cv.to_bytes(),
        &cmx.to_bytes(),
        &encrypted.kem_ciphertext,
    );
    let out_plaintext = ock.decrypt(&encrypted.out_ciphertext)?;
    parse_out_plaintext(&out_plaintext)
}

/// Decrypts one output with its recovered KEM secret and checks it against the
/// action's public data.
///
/// # Errors
/// Returns [`crypto::Error::DecryptionFailed`] if the keys do not
/// open the ciphertext, or [`Error::CoinDecryption`] if the plaintext
/// does not match the action.
pub fn decrypt_coin_with_keys(
    pk_d: &DiversifiedTransmissionKey,
    shared_secret: &KemSharedSecret,
    encrypted: &EncryptedCoin,
    rho: Rho,
    cmx: &ExtractedCoinCommitment,
) -> Result<Coin> {
    let key = shared_secret.coin_key(&encrypted.kem_ciphertext, &cmx.to_bytes());
    let plaintext = CoinPlaintext::decode(&key.decrypt(&encrypted.enc_ciphertext)?)?;
    finish_decryption(plaintext, *pk_d, rho, cmx)
}

/// Rebuilds the coin and checks it against the action's public data.
fn finish_decryption(
    plaintext: CoinPlaintext,
    pk_d: DiversifiedTransmissionKey,
    rho: Rho,
    cmx: &ExtractedCoinCommitment,
) -> Result<Coin> {
    let coin = Coin::new(
        plaintext.diversifier,
        pk_d,
        plaintext.value,
        rho,
        plaintext.rseed,
    );

    if coin.cmx()? != *cmx {
        return Err(Error::CoinDecryption("commitment mismatch"));
    }
    Ok(coin)
}

/// The decrypted contents of a coin ciphertext.
#[derive(Debug)]
struct CoinPlaintext {
    diversifier: Diversifier,
    value: RawCoin,
    rseed: RandomSeed,
}

impl CoinPlaintext {
    fn from_coin(coin: &Coin) -> Self {
        Self {
            diversifier: *coin.diversifier(),
            value: coin.value(),
            rseed: coin.rseed().clone(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(COIN_PLAINTEXT_LEN);
        w.put_u8(PLAINTEXT_VERSION)
            .put(self.diversifier.as_bytes())
            .put_u64_le(self.value.raw())
            .put(self.rseed.as_bytes());
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take_u8()? != PLAINTEXT_VERSION {
            return Err(Error::CoinDecryption("unknown plaintext version"));
        }
        let diversifier = Diversifier::from_bytes(r.take_array()?);
        let value = RawCoin::from_raw(r.take_u64_le()?)?;
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        r.finish()?;
        Ok(Self {
            diversifier,
            value,
            rseed,
        })
    }
}

/// Converts a ciphertext into its fixed-size array.
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::Malformed("unexpected ciphertext length"))
}

fn out_plaintext(
    pk_d: &DiversifiedTransmissionKey,
    ek: &TransmissionKey,
    shared_secret: &KemSharedSecret,
) -> Vec<u8> {
    let mut w = Writer::with_capacity(OUT_PLAINTEXT_LEN);
    w.put(&pk_d.to_bytes())
        .put(&ek.to_bytes())
        .put(shared_secret.as_bytes());
    w.into_bytes()
}

fn random_out_plaintext(rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    let mut bytes = vec![0u8; OUT_PLAINTEXT_LEN];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn parse_out_plaintext(
    bytes: &[u8],
) -> Result<(DiversifiedTransmissionKey, TransmissionKey, KemSharedSecret)> {
    let mut r = Reader::new(bytes);
    let pk_d = DiversifiedTransmissionKey::from_bytes(&r.take_array::<ENCODED_LEN>()?)?;
    let ek = TransmissionKey::from_bytes(r.take(KEM_ENCAPSULATION_KEY_LEN)?)?;
    let shared_secret = KemSharedSecret::from_bytes(r.take_array()?);
    r.finish()?;
    Ok((pk_d, ek, shared_secret))
}

#[cfg(test)]
mod tests {
    use crate::address::RhombusAddress as Address;
    use crate::amount::RawCoin;
    use crypto::commitment::ValueCommitTrapdoor;
    use crypto::keys::{FullViewingKey, SpendingKey};
    use crypto::pallas;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    struct Party {
        ivk: IncomingViewingKey,
        ovk: OutgoingViewingKey,
        address: Address,
    }

    fn party(rng: &mut ChaCha20Rng) -> Party {
        let fvk = FullViewingKey::derive(&SpendingKey::random(rng)).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let address = Address::derive(&ivk, Diversifier::random(rng)).unwrap();
        Party {
            ivk,
            ovk: fvk.outgoing_viewing_key(),
            address,
        }
    }

    struct Scenario {
        rng: ChaCha20Rng,
        sender: Party,
        receiver: Party,
        coin: Coin,
        cv: ValueCommitment,
        cmx: ExtractedCoinCommitment,
        encrypted: EncryptedCoin,
    }

    fn scenario(seed: u64, with_ovk: bool) -> Scenario {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sender = party(&mut rng);
        let receiver = party(&mut rng);
        let rho = Rho::from_base(pallas::Base::from(seed));
        let coin = Coin::new(
            receiver.address,
            RawCoin::from_raw(4_200).unwrap(),
            rho,
            RandomSeed::random(&mut rng),
        );
        let cv = ValueCommitment::commit(-4_200, &ValueCommitTrapdoor::random(&mut rng));
        let cmx = coin.cmx().unwrap();
        let ovk = with_ovk.then_some(&sender.ovk);
        let encrypted = encrypt_coin(&coin, ovk, &cv, &mut rng).unwrap();
        Scenario {
            rng,
            sender,
            receiver,
            coin,
            cv,
            cmx,
            encrypted,
        }
    }

    fn assert_same_coin(a: &Coin, b: &Coin) {
        assert_eq!(a.recipient(), b.recipient());
        assert_eq!(a.value(), b.value());
        assert_eq!(a.rho(), b.rho());
        assert_eq!(a.rseed().as_bytes(), b.rseed().as_bytes());
    }

    #[test]
    fn sizes_are_fixed() {
        assert_eq!(
            COIN_PLAINTEXT_LEN,
            1 + DIVERSIFIER_LEN + 8 + RANDOM_SEED_LEN
        );
        assert_eq!(COIN_CIPHERTEXT_LEN, COIN_PLAINTEXT_LEN + TAG_LEN);
    }

    #[test]
    fn receiver_decrypts_with_ivk() {
        let s = scenario(1, true);
        let (coin) =
            decrypt_coin_with_ivk(&s.receiver.ivk, &s.encrypted, *s.coin.rho(), &s.cmx).unwrap();
        assert_same_coin(&coin, &s.coin);
    }

    #[test]
    fn sender_decrypts_with_ovk() {
        let s = scenario(2, true);
        let (coin) =
            decrypt_coin_with_ovk(&s.sender.ovk, &s.encrypted, &s.cv, *s.coin.rho(), &s.cmx)
                .unwrap();
        assert_same_coin(&coin, &s.coin);
    }

    #[test]
    fn wrong_keys_fail_to_decrypt() {
        let mut s = scenario(3, true);
        let stranger = party(&mut s.rng);
        let ivk_result = decrypt_coin_with_ivk(&stranger.ivk, &s.encrypted, *s.coin.rho(), &s.cmx);
        assert_eq!(
            ivk_result.unwrap_err(),
            Error::Crypto(crypto::Error::DecryptionFailed)
        );
        let ovk_result =
            decrypt_coin_with_ovk(&stranger.ovk, &s.encrypted, &s.cv, *s.coin.rho(), &s.cmx);
        assert_eq!(
            ovk_result.unwrap_err(),
            Error::Crypto(crypto::Error::DecryptionFailed)
        );
    }

    #[test]
    fn without_ovk_the_sender_cannot_recover_the_coin() {
        let s = scenario(4, false);
        assert!(
            decrypt_coin_with_ovk(&s.sender.ovk, &s.encrypted, &s.cv, *s.coin.rho(), &s.cmx)
                .is_err()
        );
        // The receiver is unaffected.
        assert!(
            decrypt_coin_with_ivk(&s.receiver.ivk, &s.encrypted, *s.coin.rho(), &s.cmx).is_ok()
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let s = scenario(5, true);
        let mut enc = *s.encrypted.enc_ciphertext();
        enc[100] ^= 1;
        let tampered =
            EncryptedCoin::from_parts(*s.encrypted.epk(), enc, *s.encrypted.out_ciphertext());
        assert!(decrypt_coin_with_ivk(&s.receiver.ivk, &tampered, *s.coin.rho(), &s.cmx).is_err());
    }

    #[test]
    fn mismatched_commitment_is_rejected() {
        let s = scenario(6, true);
        let wrong_cmx = ExtractedCoinCommitment::from_bytes(&[1; 32]).unwrap();
        let result =
            decrypt_coin_with_ivk(&s.receiver.ivk, &s.encrypted, *s.coin.rho(), &wrong_cmx);
        assert_eq!(
            result.unwrap_err(),
            Error::CoinDecryption("commitment mismatch")
        );
    }

    #[test]
    fn mismatched_rho_is_rejected() {
        // A different rho changes the commitment, so the cmx check catches it.
        let s = scenario(7, true);
        let other_rho = Rho::from_base(pallas::Base::from(999u64));
        assert!(decrypt_coin_with_ivk(&s.receiver.ivk, &s.encrypted, other_rho, &s.cmx).is_err());
    }

    #[test]
    fn plaintext_roundtrips_and_rejects_bad_version_and_length() {
        let s = scenario(8, true);
        let encoded = CoinPlaintext::from_coin(&s.coin).encode();
        assert_eq!(encoded.len(), COIN_PLAINTEXT_LEN);
        let decoded = CoinPlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded.value, s.coin.value());

        let mut bad_version = encoded.clone();
        bad_version[0] = 0x02;
        assert_eq!(
            CoinPlaintext::decode(&bad_version).unwrap_err(),
            Error::CoinDecryption("unknown plaintext version")
        );
        assert!(matches!(
            CoinPlaintext::decode(&encoded[..10]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn plaintext_accepts_the_full_raw_amount_range() {
        let s = scenario(9, true);
        let mut encoded = CoinPlaintext::from_coin(&s.coin).encode();
        encoded[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            CoinPlaintext::decode(&encoded).unwrap().value.raw(),
            u64::MAX
        );
    }

    #[test]
    fn out_plaintext_roundtrips() {
        let s = scenario(10, true);
        let esk = s.coin.esk();
        let bytes = out_plaintext(s.coin.recipient().pk_d(), &esk);
        let (pk_d, parsed) = parse_out_plaintext(&bytes).unwrap();
        assert_eq!(&pk_d, s.coin.recipient().pk_d());
        assert_eq!(parsed.to_bytes(), esk.to_bytes());
    }

    #[test]
    fn encrypted_coin_roundtrips_and_rejects_identity_epk() {
        let s = scenario(11, true);
        let bytes = s.encrypted.to_vec();
        assert_eq!(bytes.len(), ENCRYPTED_COIN_LEN);
        assert_eq!(EncryptedCoin::from_slice(&bytes), Ok(s.encrypted.clone()));
        let mut bad = bytes;
        bad[..32].copy_from_slice(&[0; 32]);
        assert!(EncryptedCoin::from_slice(&bad).is_err());
    }
}
