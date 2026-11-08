//! Diversified payment addresses.
//!
//! An address is a diversifier plus the transmission key derived from it.
//! Raw encoding is `d || pk_d` (43 bytes). Text encoding is Base58Check of
//! the raw address and a network-bound checksum, without a textual prefix.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto::diversifier::DiversifierIndex;
use crypto::encoding::{Encoded, ENCODED_LEN};
use crypto::hash::{blake2b_short, ADDRESS_CHECKSUM};
use crypto::keys::{
    DiversifiedTransmissionKey, Diversifier, FullViewingKey, IncomingViewingKey, DIVERSIFIER_LEN,
};
use crypto::pallas;

use crate::bytes::{Encodable, Reader, Writer};
use crate::{Error, Result};

/// A chain network identifier used to bind payment address checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressPrefix {
    /// The main network.
    Main,
    /// A test network.
    Test,
}

impl AddressPrefix {
    const fn tag(self) -> u8 {
        match self {
            Self::Main => b'd',
            Self::Test => b't',
        }
    }
}

/// Length of the raw address encoding.
pub const ADDRESS_LEN: usize = DIVERSIFIER_LEN + ENCODED_LEN;

/// A shielded payment address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhombusAddress {
    diversifier: Diversifier,
    pk_d: DiversifiedTransmissionKey,
}

impl RhombusAddress {
    /// Derives the address for `diversifier` under `ivk`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn derive(ivk: &IncomingViewingKey, diversifier: Diversifier) -> Result<Self> {
        Ok(Self {
            diversifier,
            pk_d: ivk.transmission_key(&diversifier)?,
        })
    }

    /// The address at `index` of the wallet owning `fvk`.
    ///
    /// # Errors
    /// Fails if key derivation or the diversifier is invalid.
    pub fn from_index(fvk: &FullViewingKey, index: DiversifierIndex) -> Result<Self> {
        let diversifier = fvk.diversifier_key().diversifier(index)?;
        Self::derive(&fvk.incoming_viewing_key()?, diversifier)
    }

    /// Builds an address from already validated parts.
    pub fn from_parts(diversifier: Diversifier, pk_d: DiversifiedTransmissionKey) -> Self {
        Self { diversifier, pk_d }
    }

    /// The diversifier.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// The transmission key.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    /// The diversified base `g_d`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn g_d(&self) -> Result<pallas::Point> {
        Ok(self.diversifier.base()?)
    }

    /// Raw encoding `d || pk_d`.
    pub fn to_bytes(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0u8; ADDRESS_LEN];
        let (d, pk) = out.split_at_mut(DIVERSIFIER_LEN);
        d.copy_from_slice(self.diversifier.as_bytes());
        pk.copy_from_slice(&self.pk_d.to_bytes());
        out
    }

    /// Parses the raw encoding, validating both parts.
    ///
    /// # Errors
    /// Fails on wrong length, invalid diversifier, or invalid transmission key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: &[u8; ADDRESS_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidAddress("wrong length".into()))?;
        let (d, pk) = raw.split_at(DIVERSIFIER_LEN);
        let diversifier = Diversifier::from_bytes(array_from(d)?);
        diversifier.base()?;
        let pk_d = DiversifiedTransmissionKey::from_bytes(&array_from::<ENCODED_LEN>(pk)?)?;
        Ok(Self::from_parts(diversifier, pk_d))
    }

    /// Base58Check of the raw address and network-bound checksum, without HRP.
    pub fn encode(&self, prefix: AddressPrefix) -> String {
        const CHECKSUM_LEN: usize = 4;
        let raw = self.to_bytes();
        let checksum = blake2b_short(ADDRESS_CHECKSUM, &[&[prefix.tag() as u8], &raw]);
        let mut payload = Vec::with_capacity(ADDRESS_LEN + CHECKSUM_LEN);
        payload.extend_from_slice(&raw);
        payload.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        base58_encode(&payload)
    }

    /// Parses the unprefixed, network-bound Base58Check form. The previous
    /// network-bound tagged Base64URL form remains accepted for migration.
    ///
    /// # Errors
    /// Fails on a wrong network, checksum, encoding, invalid diversifier, or key.
    pub fn decode(text: &str, prefix: AddressPrefix) -> Result<Self> {
        const CHECKSUM_LEN: usize = 4;
        const PAYLOAD_LEN: usize = ADDRESS_LEN + CHECKSUM_LEN;
        // A 47-byte payload needs at most 65 Base58 characters. Check
        // before allocating a decode buffer proportional to user input.
        if text.len() > 65 {
            return Err(Error::InvalidAddress("wrong length".into()));
        }

        // Prefer a valid Base58Check interpretation. Some canonical
        // Base58 strings are 64 characters and also look like the old
        // `d`/`t` + Base64URL format, so legacy detection must not take
        // precedence over a valid current address.
        if let Ok(payload) = base58_decode(text) {
            if base58_encode(&payload) == text && payload.len() == PAYLOAD_LEN {
                if let Ok(address) = Self::decode_check_payload(&payload, prefix) {
                    return Ok(address);
                }
            }
        }

        // Previous releases emitted a leading `d`/`t` and then 63
        // Base64URL characters. Keep accepting them if they were not a
        // valid Base58Check address; encoding emits only Base58Check.
        let legacy_encoded = text
            .strip_prefix(prefix.tag() as char)
            .filter(|s| s.len() == 63);
        if let Some(encoded) = legacy_encoded {
            let payload = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| Error::InvalidAddress("invalid legacy address encoding".into()))?;
            if URL_SAFE_NO_PAD.encode(&payload) != encoded {
                return Err(Error::InvalidAddress(
                    "non-canonical address encoding".into(),
                ));
            }
            return Self::decode_check_payload(&payload, prefix);
        }

        let payload = base58_decode(text)?;
        if base58_encode(&payload) != text {
            return Err(Error::InvalidAddress("non-canonical Base58".into()));
        }
        Self::decode_check_payload(&payload, prefix)
    }

    fn decode_check_payload(payload: &[u8], prefix: AddressPrefix) -> Result<Self> {
        const CHECKSUM_LEN: usize = 4;
        if payload.len() != ADDRESS_LEN + CHECKSUM_LEN {
            return Err(Error::InvalidAddress("wrong length".into()));
        }
        let (raw, checksum) = payload.split_at(ADDRESS_LEN);
        let expected = blake2b_short(ADDRESS_CHECKSUM, &[&[prefix.tag()], raw]);
        if checksum != &expected[..CHECKSUM_LEN] {
            return Err(Error::InvalidAddress("checksum mismatch".into()));
        }
        Self::from_bytes(raw)
    }
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut input = bytes.to_vec();
    let mut start = zeros;
    let mut encoded = Vec::with_capacity(bytes.len().saturating_mul(138) / 100 + 1);
    while start < input.len() {
        let mut remainder = 0u32;
        for byte in &mut input[start..] {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(value / 58).unwrap_or(0);
            remainder = value % 58;
        }
        encoded.push(BASE58[usize::try_from(remainder).unwrap_or(0)]);
        while start < input.len() && input[start] == 0 {
            start += 1;
        }
    }
    encoded.extend(core::iter::repeat_n(b'1', zeros));
    encoded.reverse();
    String::from_utf8(encoded).unwrap_or_default()
}

fn base58_decode(text: &str) -> Result<Vec<u8>> {
    let input = text.as_bytes();
    let zeros = input.iter().take_while(|byte| **byte == b'1').count();
    let mut decoded = vec![0u8; input.len().saturating_mul(733) / 1000 + 1];
    let mut length = 0usize;
    for &character in &input[zeros..] {
        let value = BASE58
            .iter()
            .position(|candidate| *candidate == character)
            .ok_or_else(|| Error::InvalidAddress("invalid Base58 character".into()))?;
        let mut carry = u32::try_from(value).unwrap_or(0);
        let mut used = 0usize;
        for byte in decoded.iter_mut().rev() {
            if carry == 0 && used >= length {
                break;
            }
            carry += 58 * u32::from(*byte);
            *byte = u8::try_from(carry & 0xff).unwrap_or(0);
            carry >>= 8;
            used += 1;
        }
        if carry != 0 {
            return Err(Error::InvalidAddress("Base58 value out of range".into()));
        }
        length = used;
    }
    let first = decoded.len().saturating_sub(length);
    let significant = decoded[first..]
        .iter()
        .position(|byte| *byte != 0)
        .map_or(decoded.len(), |offset| first + offset);
    let mut bytes = vec![0; zeros];
    bytes.extend_from_slice(&decoded[significant..]);
    Ok(bytes)
}

impl Encodable for RhombusAddress {
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

/// Alias documenting that transmission keys use the common encoding.
pub type TransmissionKeyBytes = Encoded;

#[cfg(test)]
mod tests {
    use crypto::keys::{FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    pub(crate) fn address(seed: u64) -> RhombusAddress {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ivk = FullViewingKey::derive(&SpendingKey::random(&mut rng))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        RhombusAddress::derive(&ivk, Diversifier::random(&mut rng)).unwrap()
    }

    #[test]
    fn raw_encoding_roundtrips() {
        let addr = address(1);
        assert_eq!(RhombusAddress::from_bytes(&addr.to_bytes()), Ok(addr));
    }

    #[test]
    fn encodable_matches_raw_encoding() {
        let addr = address(9);
        assert_eq!(addr.to_vec(), addr.to_bytes().to_vec());
        assert_eq!(RhombusAddress::from_slice(&addr.to_vec()), Ok(addr));
    }

    #[test]
    fn raw_encoding_rejects_wrong_length_and_garbage() {
        assert!(RhombusAddress::from_bytes(&[0u8; ADDRESS_LEN - 1]).is_err());
        assert!(RhombusAddress::from_bytes(&[0xFF; ADDRESS_LEN]).is_err());
    }

    #[test]
    fn text_encoding_roundtrips_as_unprefixed_network_bound_base58() {
        let addr = address(2);
        let main = addr.encode(AddressPrefix::Main);
        let test = addr.encode(AddressPrefix::Test);
        assert!(!main.contains('-') && !main.contains('_'));
        assert!(main.len() < ADDRESS_LEN * 2 + 1);
        assert_ne!(main, test);
        assert_eq!(RhombusAddress::decode(&main, AddressPrefix::Main), Ok(addr));
        assert_eq!(RhombusAddress::decode(&test, AddressPrefix::Test), Ok(addr));
    }

    #[test]
    fn base58_addresses_reject_the_other_network() {
        let addr = address(2);
        let main = addr.encode(AddressPrefix::Main);
        assert!(RhombusAddress::decode(&main, AddressPrefix::Test).is_err());
    }

    #[test]
    fn text_encoding_rejects_invalid_base58() {
        let mut text = address(3).encode(AddressPrefix::Main);
        let last = text.len().saturating_sub(1);
        text.replace_range(last.., "!");
        assert!(RhombusAddress::decode(&text, AddressPrefix::Main).is_err());
    }

    #[test]
    fn a_base58_address_that_looks_like_legacy_base64_stays_base58() {
        let mut rng = ChaCha20Rng::seed_from_u64(31);
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut rng)).unwrap();
        for index in 0..10_000 {
            let address = RhombusAddress::from_index(&fvk, DiversifierIndex::from(index)).unwrap();
            let text = address.encode(AddressPrefix::Main);
            // A 64-character Base58 string beginning with `d` enters the old
            // heuristic. The final character also makes the 63-character
            // suffix a canonical unpadded Base64URL candidate.
            if text.len() == 64
                && text.starts_with('d')
                && "AQgw".contains(text.chars().last().unwrap())
            {
                assert_eq!(
                    RhombusAddress::decode(&text, AddressPrefix::Main),
                    Ok(address)
                );
                return;
            }
        }
        panic!("did not find a deterministic Base58/legacy-shaped address");
    }

    #[test]
    fn address_decoder_rejects_oversized_text_before_base58_decode() {
        let text = "1".repeat(66);
        assert!(RhombusAddress::decode(&text, AddressPrefix::Main).is_err());
    }

    #[test]
    fn decoder_rejects_network_unbound_legacy_hex_addresses() {
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
        assert!(RhombusAddress::decode(&legacy, AddressPrefix::Main).is_err());
        assert!(RhombusAddress::decode(&legacy, AddressPrefix::Test).is_err());
    }

    #[test]
    fn decoder_keeps_accepting_network_bound_legacy_base64_addresses() {
        for seed in 0..100 {
            let address = address(seed);
            let raw = address.to_bytes();
            let checksum = blake2b_short(ADDRESS_CHECKSUM, &[b"d", &raw]);
            let mut payload = raw.to_vec();
            payload.extend_from_slice(&checksum[..4]);
            let encoded = URL_SAFE_NO_PAD.encode(payload);
            // Force Base58 parsing to reject this spelling so the test
            // exercises the retained migration path.
            if encoded.contains('-') || encoded.contains('_') {
                let legacy = format!("d{encoded}");
                assert_eq!(
                    RhombusAddress::decode(&legacy, AddressPrefix::Main),
                    Ok(address)
                );
                return;
            }
        }
        panic!("did not find a legacy Base64URL address with non-Base58 characters");
    }

    #[test]
    fn base58_roundtrips_leading_zero_bytes() {
        for bytes in [&[][..], &[0][..], &[0, 0, 1][..], &[0, 0, 0, 255][..]] {
            let encoded = base58_encode(bytes);
            assert_eq!(base58_decode(&encoded).unwrap(), bytes);
        }
    }

    #[test]
    fn indexed_addresses_are_deterministic_distinct_and_recoverable() {
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(8)))
            .unwrap();
        let a0 = RhombusAddress::from_index(&fvk, DiversifierIndex::ZERO).unwrap();
        assert_eq!(
            a0,
            RhombusAddress::from_index(&fvk, DiversifierIndex::ZERO).unwrap()
        );
        let a1 = RhombusAddress::from_index(&fvk, DiversifierIndex::from(1)).unwrap();
        assert_ne!(a0, a1);
        let recovered = fvk.diversifier_key().index(a1.diversifier()).unwrap();
        assert_eq!(recovered, DiversifierIndex::from(1));
    }

    #[test]
    fn different_diversifiers_give_different_addresses() {
        assert_ne!(address(6), address(7));
    }
}
