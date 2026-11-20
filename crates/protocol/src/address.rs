//! Diversified payment addresses.
//!
//! An address contains a diversifier, a diversified Pallas transmission key,
//! and an ML-KEM encapsulation key. New addresses derive a separate ML-KEM key
//! per diversifier. Raw encoding is `d || pk_d || ek`.
//! Text encoding is a network prefix followed by lowercase hexadecimal of the
//! raw address and a network-bound checksum.
use crypto::diversifier::DiversifierIndex;
use crypto::encoding::ENCODED_LEN;
use crypto::encryption::{TransmissionKey, KEM_ENCAPSULATION_KEY_LEN};
use crypto::hash::{blake2b_short, ADDRESS_CHECKSUM};
use crypto::keys::{DiversifiedTransmissionKey, Diversifier, FullViewingKey, DIVERSIFIER_LEN};
use crypto::pallas;

use crate::bytes::{Encodable, Reader, Writer};
use crate::{Error, Result};

/// A chain network identifier used to bind payment address checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// The main network.
    Main,
    /// A test network.
    Test,
}

impl Network {
    /// The text prefix for this network's payment addresses.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Main => "kr",
            Self::Test => "tkr",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Main => b'd',
            Self::Test => b't',
        }
    }
}

/// Length of the raw address encoding.
pub const ADDRESS_LEN: usize = DIVERSIFIER_LEN + ENCODED_LEN + KEM_ENCAPSULATION_KEY_LEN;
const CHECKSUM_LEN: usize = 4;

/// A shielded payment address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KryptosAddress {
    diversifier: Diversifier,
    pk_d: DiversifiedTransmissionKey,
    ek: TransmissionKey,
}

impl KryptosAddress {
    /// Derives an address with a separate ML-KEM key for `diversifier`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn derive(fvk: &FullViewingKey, diversifier: Diversifier) -> Result<Self> {
        let ek = fvk.receiver_key_for_diversifier(&diversifier).1;
        Self::build(fvk, diversifier, ek)
    }

    /// The address at `index` of the wallet owning `fvk`.
    ///
    /// # Errors
    /// Fails if key derivation or the diversifier is invalid.
    pub fn from_index(fvk: &FullViewingKey, index: DiversifierIndex) -> Result<Self> {
        Self::derive(fvk, fvk.diversifier_key().diversifier(index)?)
    }

    fn build(fvk: &FullViewingKey, diversifier: Diversifier, ek: TransmissionKey) -> Result<Self> {
        let ivk = fvk.incoming_viewing_key()?;
        Ok(Self {
            diversifier,
            pk_d: ivk.transmission_key(&diversifier)?,
            ek,
        })
    }

    /// Builds an address from already validated parts.
    pub(crate) fn from_parts(
        diversifier: Diversifier,
        pk_d: DiversifiedTransmissionKey,
        ek: TransmissionKey,
    ) -> Self {
        Self {
            diversifier,
            pk_d,
            ek,
        }
    }

    /// The diversifier.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// The transmission key.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    /// The ML-KEM encapsulation key carried by this address.
    pub fn kem_key(&self) -> &TransmissionKey {
        &self.ek
    }

    /// The diversified base `g_d`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn g_d(&self) -> Result<pallas::Point> {
        Ok(self.diversifier.base()?)
    }

    /// Raw encoding `d || pk_d || ek`.
    pub fn to_bytes(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0u8; ADDRESS_LEN];
        let (d, rest) = out.split_at_mut(DIVERSIFIER_LEN);
        let (pk, ek) = rest.split_at_mut(ENCODED_LEN);
        d.copy_from_slice(self.diversifier.as_bytes());
        pk.copy_from_slice(&self.pk_d.to_bytes());
        ek.copy_from_slice(&self.ek.to_bytes());
        out
    }

    /// Parses the raw encoding, validating both parts.
    ///
    /// # Errors
    /// Fails on wrong length, invalid diversifier, or invalid key encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: &[u8; ADDRESS_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidAddress("wrong length".into()))?;
        let (d, rest) = raw.split_at(DIVERSIFIER_LEN);
        let (pk, ek) = rest.split_at(ENCODED_LEN);
        let diversifier = Diversifier::from_bytes(array_from(d)?);
        diversifier.base()?;
        let pk_d = DiversifiedTransmissionKey::from_bytes(&array_from::<ENCODED_LEN>(pk)?)?;
        let ek = TransmissionKey::from_bytes(ek)?;
        Ok(Self::from_parts(diversifier, pk_d, ek))
    }

    /// Network prefix followed by lowercase hexadecimal of the address and checksum.
    pub fn encode(&self, network: Network) -> String {
        let raw = self.to_bytes();
        let checksum = blake2b_short(ADDRESS_CHECKSUM, &[&[network.tag()], &raw]);
        let mut payload = Vec::with_capacity(ADDRESS_LEN + CHECKSUM_LEN);
        payload.extend_from_slice(&raw);
        payload.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        format!("{}{}", network.prefix(), hex_encode(&payload))
    }

    /// Parses the prefixed, lowercase, network-bound hexadecimal address form.
    ///
    /// # Errors
    /// Fails on wrong length, invalid hex, wrong network, checksum, diversifier, or key.
    pub fn decode(text: &str, network: Network) -> Result<Self> {
        let text = text
            .strip_prefix(network.prefix())
            .ok_or_else(|| Error::InvalidAddress("wrong network prefix".into()))?;
        if text.len() != (ADDRESS_LEN + CHECKSUM_LEN) * 2 {
            return Err(Error::InvalidAddress("wrong length".into()));
        }

        let payload = hex_decode(text)?;
        let (raw, checksum) = payload.split_at(ADDRESS_LEN);
        let expected = blake2b_short(ADDRESS_CHECKSUM, &[&[network.tag()], raw]);
        if checksum != &expected[..CHECKSUM_LEN] {
            return Err(Error::InvalidAddress("checksum mismatch".into()));
        }
        Self::from_bytes(raw)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(Error::InvalidAddress("invalid hexadecimal length".into()));
    }

    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])
            .ok_or_else(|| Error::InvalidAddress("invalid hexadecimal character".into()))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| Error::InvalidAddress("invalid hexadecimal character".into()))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl Encodable for KryptosAddress {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(ADDRESS_LEN)?)
    }
}

/// Copies a slice into a fixed array, or reports a length mismatch.
fn array_from<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice
        .try_into()
        .map_err(|_| Error::InvalidAddress("wrong length".into()))
}

#[cfg(test)]
mod tests {
    use crypto::keys::{FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    pub(crate) fn address(seed: u64) -> KryptosAddress {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut rng)).unwrap();
        KryptosAddress::derive(&fvk, Diversifier::random(&mut rng)).unwrap()
    }

    #[test]
    fn raw_encoding_roundtrips() {
        let addr = address(1);
        assert_eq!(KryptosAddress::from_bytes(&addr.to_bytes()), Ok(addr));
    }

    #[test]
    fn encodable_matches_raw_encoding() {
        let addr = address(9);
        assert_eq!(addr.to_vec(), addr.to_bytes().to_vec());
        assert_eq!(KryptosAddress::from_slice(&addr.to_vec()), Ok(addr));
    }

    #[test]
    fn raw_encoding_rejects_wrong_length_and_garbage() {
        assert!(KryptosAddress::from_bytes(&[0u8; ADDRESS_LEN - 1]).is_err());
        assert!(KryptosAddress::from_bytes(&[0xFF; ADDRESS_LEN]).is_err());
    }

    #[test]
    fn text_encoding_roundtrips_as_network_bound_hex() {
        let addr = address(2);
        let main = addr.encode(Network::Main);
        let test = addr.encode(Network::Test);
        assert_eq!(main.len(), 2 + (ADDRESS_LEN + 4) * 2);
        assert_eq!(test.len(), 3 + (ADDRESS_LEN + 4) * 2);
        assert!(main.starts_with("kr"));
        assert!(test.starts_with("tkr"));
        assert!(main
            .strip_prefix("kr")
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(main, test);
        assert_eq!(
            KryptosAddress::decode(&main, Network::Main),
            Ok(addr.clone())
        );
        assert_eq!(KryptosAddress::decode(&test, Network::Test), Ok(addr));
    }

    #[test]
    fn hex_addresses_reject_the_other_network() {
        let addr = address(2);
        let main = addr.encode(Network::Main);
        assert!(KryptosAddress::decode(&main, Network::Test).is_err());
    }

    #[test]
    fn decoder_rejects_missing_or_replaced_prefix() {
        let main = address(2).encode(Network::Main);
        let payload = main.strip_prefix("kr").unwrap();
        assert!(KryptosAddress::decode(payload, Network::Main).is_err());
        assert!(KryptosAddress::decode(&format!("tkr{payload}"), Network::Test).is_err());
    }

    #[test]
    fn text_encoding_rejects_invalid_hex() {
        let mut text = address(3).encode(Network::Main);
        let last = text.len().saturating_sub(1);
        text.replace_range(last.., "!");
        assert!(KryptosAddress::decode(&text, Network::Main).is_err());
    }

    #[test]
    fn decoder_rejects_uppercase_hex_addresses() {
        let address = address(32);
        let uppercase = address.encode(Network::Main).to_uppercase();
        assert!(KryptosAddress::decode(&uppercase, Network::Main).is_err());
    }

    #[test]
    fn decoder_rejects_colon_delimited_address_text() {
        let address = address(32);
        let raw = address.to_bytes();
        let diversifier = raw[..DIVERSIFIER_LEN]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let pk_d = raw[DIVERSIFIER_LEN..]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let legacy = format!("{diversifier}:{pk_d}");
        assert!(KryptosAddress::decode(&legacy, Network::Main).is_err());
        assert!(KryptosAddress::decode(&legacy, Network::Test).is_err());
    }

    #[test]
    fn hex_roundtrips_leading_zero_bytes() {
        for bytes in [&[][..], &[0][..], &[0, 0, 1][..], &[0, 0, 0, 255][..]] {
            let encoded = hex_encode(bytes);
            assert_eq!(hex_decode(&encoded).unwrap(), bytes);
        }
    }

    #[test]
    fn indexed_addresses_are_deterministic_distinct_and_recoverable() {
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(8)))
            .unwrap();
        let a0 = KryptosAddress::from_index(&fvk, DiversifierIndex::ZERO).unwrap();
        assert_eq!(
            a0,
            KryptosAddress::from_index(&fvk, DiversifierIndex::ZERO).unwrap()
        );
        let a1 = KryptosAddress::from_index(&fvk, DiversifierIndex::from(1)).unwrap();
        assert_ne!(a0, a1);
        assert_ne!(a0.kem_key(), a1.kem_key());
        let restored = FullViewingKey::from_bytes(&fvk.to_bytes()).unwrap();
        assert_eq!(
            a1,
            KryptosAddress::from_index(&restored, DiversifierIndex::from(1)).unwrap()
        );
        let recovered = fvk.diversifier_key().index(a1.diversifier()).unwrap();
        assert_eq!(recovered, DiversifierIndex::from(1));
    }

    #[test]
    fn different_diversifiers_give_different_addresses() {
        assert_ne!(address(6), address(7));
    }
}
