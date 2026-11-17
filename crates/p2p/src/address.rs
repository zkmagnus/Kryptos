//! Tor v3 service identities and their address encoding.

use core::fmt;
use core::str::FromStr;

use protocol::bytes::{Reader, Writer};
use safelog::DisplayRedacted;
use tor_hscrypto::pk::HsId;

use crate::{Error, Result};

/// BIP155 network identifier for a Tor v3 public key.
pub const TOR_V3_NETWORK_ID: u8 = 4;
/// Encoded length of a Tor v3 identity, excluding its port.
pub const TOR_V3_ADDRESS_LEN: usize = 34;

/// A supported peer identity. Other network types are rejected on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetAddr {
    /// Ed25519 identity public key of a Tor v3 onion service.
    TorV3([u8; 32]),
}

/// One service identity and its virtual P2P port.
pub type PeerKey = (NetAddr, u16);

/// Whether `own` is the canonical dialer for a verified pair of onion identities.
/// Public-key byte order gives both nodes the same choice without timestamps or
/// nonce grinding. Equal identities are self-connections, so neither should dial.
/// Apply this only after the reverse connection has been securely linked; a
/// claimed inbound address must never evict an authenticated outbound stream.
pub fn canonical_dialer(own: NetAddr, remote: NetAddr) -> bool {
    own < remote
}

impl NetAddr {
    /// Parses an onion hostname followed by its virtual port.
    ///
    /// # Errors
    /// Rejects malformed onion names, missing ports, and zero ports.
    pub fn parse_endpoint(value: &str) -> Result<PeerKey> {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or(Error::BadAddress("missing onion service port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::BadAddress("invalid onion service port"))?;
        if port == 0 {
            return Err(Error::BadAddress("zero onion service port"));
        }
        Ok((host.parse()?, port))
    }

    /// The onion endpoint accepted by [`Self::parse_endpoint`].
    pub fn endpoint(self, port: u16) -> String {
        format!("{self}:{port}")
    }

    /// Writes the extensible BIP155-style address, followed by a big-endian port.
    pub(crate) fn write(self, port: u16, writer: &mut Writer) {
        match self {
            Self::TorV3(public_key) => {
                writer
                    .put_u8(TOR_V3_NETWORK_ID)
                    .put_u8(32)
                    .put(&public_key)
                    .put(&port.to_be_bytes());
            }
        }
    }

    /// Reads only the Tor v3 network and its exact 32-byte payload.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<PeerKey> {
        if reader.take_u8()? != TOR_V3_NETWORK_ID {
            return Err(Error::BadAddress("unsupported address network"));
        }
        if reader.take_u8()? != 32 {
            return Err(Error::BadAddress("invalid Tor v3 public key length"));
        }
        let address = Self::TorV3(reader.take_array()?);
        let port = u16::from_be_bytes(reader.take_array()?);
        if port == 0 {
            return Err(Error::BadAddress("zero onion service port"));
        }
        Ok((address, port))
    }
}

impl fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::TorV3(public_key) = self;
        fmt::Display::fmt(&HsId::from(*public_key).display_unredacted(), formatter)
    }
}

impl FromStr for NetAddr {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let name = value
            .strip_suffix(".onion")
            .filter(|name| name.len() == 56)
            .ok_or(Error::BadAddress("expected a Tor v3 onion hostname"))?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(Error::BadAddress("invalid lowercase onion base32"));
        }
        let identity: HsId = value
            .parse()
            .map_err(|_| Error::BadAddress("invalid Tor v3 onion identity"))?;
        Ok(Self::TorV3(*identity.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::NetAddr;
    use data_encoding::BASE32_NOPAD;
    use sha3::{Digest, Sha3_256};

    fn checksum(public_key: &[u8; 32], version: u8) -> [u8; 2] {
        let mut hash = Sha3_256::new();
        hash.update(b".onion checksum");
        hash.update(public_key);
        hash.update([version]);
        let digest = hash.finalize();
        let mut result = [0; 2];
        result.copy_from_slice(digest.get(..2).unwrap());
        result
    }
    use protocol::bytes::{Reader, Writer};

    #[test]
    fn the_lower_onion_is_the_unique_dialer_in_both_directions() {
        let lower = NetAddr::TorV3([1; 32]);
        let higher = NetAddr::TorV3([2; 32]);
        assert!(super::canonical_dialer(lower, higher));
        assert!(!super::canonical_dialer(higher, lower));
        assert!(!super::canonical_dialer(lower, lower));
    }

    #[test]
    fn known_onion_vector_and_endpoint_roundtrip() {
        let hostname = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion";
        let address = NetAddr::TorV3([0; 32]);
        assert_eq!(address.to_string(), hostname);
        assert_eq!(hostname.parse::<NetAddr>().unwrap(), address);
        assert_eq!(
            NetAddr::parse_endpoint(&address.endpoint(19000)).unwrap(),
            (address, 19000)
        );
    }

    #[test]
    fn invalid_onions_and_ports_are_rejected() {
        let valid = NetAddr::TorV3([7; 32]).to_string();
        let mut bad_checksum = valid.clone().into_bytes();
        if let Some(byte) = bad_checksum.first_mut() {
            *byte = if *byte == b'a' { b'b' } else { b'a' };
        }
        assert!(String::from_utf8(bad_checksum)
            .unwrap()
            .parse::<NetAddr>()
            .is_err());
        let mut version = vec![7; 32];
        version.extend_from_slice(&checksum(&[7; 32], 2));
        version.push(2);
        assert!(format!(
            "{}.onion",
            BASE32_NOPAD.encode(&version).to_ascii_lowercase()
        )
        .parse::<NetAddr>()
        .is_err());
        for invalid in [
            "localhost",
            "127.0.0.1",
            "abc.onion",
            "aaaaaaaaaaaaaaaa.onion",
        ] {
            assert!(invalid.parse::<NetAddr>().is_err());
        }
        assert!(valid.to_ascii_uppercase().parse::<NetAddr>().is_err());
        assert!(NetAddr::parse_endpoint(&format!("{valid}:0")).is_err());
        assert!(NetAddr::parse_endpoint(&format!("{valid}:65536")).is_err());
    }

    #[test]
    fn addrv2_accepts_only_exact_tor_v3_payloads() {
        let address = NetAddr::TorV3([9; 32]);
        let mut writer = Writer::default();
        address.write(0x1234, &mut writer);
        let wire = writer.into_bytes();
        assert_eq!(wire.get(..2), Some([4, 32].as_slice()));
        assert_eq!(wire.get(34..), Some([0x12, 0x34].as_slice()));
        let mut reader = Reader::new(&wire);
        assert_eq!(NetAddr::read(&mut reader).unwrap(), (address, 0x1234));
        reader.finish().unwrap();
        for network in [0, 1, 2, 3, 5, 255] {
            let mut bad = wire.clone();
            *bad.first_mut().unwrap() = network;
            assert!(NetAddr::read(&mut Reader::new(&bad)).is_err());
        }
        let mut bad_len = wire.clone();
        *bad_len.get_mut(1).unwrap() = 31;
        assert!(NetAddr::read(&mut Reader::new(&bad_len)).is_err());
        for end in 0..wire.len() {
            assert!(NetAddr::read(&mut Reader::new(&wire[..end])).is_err());
        }
    }

    proptest! {
        #[test]
        fn canonical_dialer_is_antisymmetric(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            let a = NetAddr::TorV3(a);
            let b = NetAddr::TorV3(b);
            if a == b {
                prop_assert!(!super::canonical_dialer(a, b));
            } else {
                prop_assert_ne!(super::canonical_dialer(a, b), super::canonical_dialer(b, a));
            }
        }

        #[test]
        fn arbitrary_tor_keys_roundtrip(key in any::<[u8; 32]>(), port in 1u16..=u16::MAX) {
            let address = NetAddr::TorV3(key);
            prop_assert_eq!(address.to_string().parse::<NetAddr>().unwrap(), address);
            let mut writer = Writer::default();
            address.write(port, &mut writer);
            prop_assert_eq!(NetAddr::read(&mut Reader::new(&writer.into_bytes())).unwrap(), (address, port));
        }
    }
}
