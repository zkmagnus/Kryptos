//! Node configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use chain::genesis::genesis;
use chain::params::ChainParams;
use protocol::address::{AddressPrefix, RhombusAddress};
use protocol::block::BlockHash;

use crate::rpc::Token;
pub use crate::tor::TorConfig;

/// Outbound connections the node tries to keep.
pub const OUTBOUND_TARGET: usize = 8;
/// Transactions the mempool holds.
pub const MEMPOOL_CAPACITY: usize = 10_000;
/// Inbound connections accepted at once, by default.
pub const DEFAULT_MAX_INBOUND: usize = 32;

/// Default virtual onion port for P2P streams.
pub const DEFAULT_P2P_PORT: u16 = 19000;

/// Which network to join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Provisional main network parameters.
    Main,
    /// Separate `RandomX` key and short block interval for local testing.
    Test,
}

impl Network {
    /// Every network.
    pub const ALL: [Self; 2] = [Self::Main, Self::Test];

    /// The chain parameters.
    pub fn params(self) -> ChainParams {
        match self {
            Self::Main => ChainParams::mainnet(),
            Self::Test => ChainParams::test(),
        }
    }

    /// Whether mining waits for a connected peer.
    ///
    /// Mining is permitted without peers on both networks. A node still
    /// pauses while it is synchronizing or while a connected peer advertises
    /// a higher, unsettled tip.
    pub fn mines_only_with_peers(self) -> bool {
        false
    }

    /// How this network's addresses are written.
    pub fn address_prefix(self) -> AddressPrefix {
        self.params().address_prefix
    }

    /// The network whose genesis block has `hash`, so a command talking
    /// to a node learns which network's addresses to accept.
    pub fn for_genesis(hash: &BlockHash) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|network| genesis(&network.params()).hash() == *hash)
    }

    /// Built-in onion bootstrap peers. Rhombus has none configured;
    /// pass `--seed`, `--addnode` or `--connect` to use a custom peer.
    pub fn seeds(self) -> &'static [&'static str] {
        &[]
    }
}

impl core::fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Main => "main",
            Self::Test => "test",
        })
    }
}

impl core::str::FromStr for Network {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "main" => Ok(Self::Main),
            "test" => Ok(Self::Test),
            other => Err(format!("unknown network {other}, expected main or test")),
        }
    }
}

/// Everything a node needs to start.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent startup options, not mutually exclusive states.
pub struct Config {
    /// The network.
    pub network: Network,
    /// Directory holding the persistent chain database and peer book.
    pub datadir: PathBuf,
    /// Remove this directory when a test node shuts down.
    pub cleanup_datadir: bool,
    /// Disable external Tor networking for an offline embedded node.
    /// Local in-process APIs and explicitly configured loopback RPC remain available.
    pub offline: bool,
    /// Whether to accept P2P streams on the embedded onion service.
    pub p2p: bool,
    /// Onion peers to dial at startup, as `<v3-address>.onion:port`.
    pub connect: Vec<String>,
    /// Persistent extra onion peers to maintain.
    pub addnode: Vec<String>,
    /// Disable built-in bootstrap peers.
    pub no_seeds: bool,
    /// Maximum regular outbound peers; zero also disables verification probes.
    pub max_outbound: usize,
    /// Embedded Tor onion-service configuration.
    pub tor: TorConfig,
    /// Mine to this address, or `None` to not mine.
    pub mine_to: Option<RhombusAddress>,
    /// Miner worker threads when mining. At least one.
    pub mining_threads: usize,
    /// Local control socket, or `None` for none.
    pub rpc: Option<SocketAddr>,
    /// JSON-RPC 2.0 over HTTP, or `None` for none. Shares the control
    /// socket's token.
    pub rpc_http: Option<SocketAddr>,
    /// Token the control socket demands; generated when `None`.
    pub rpc_token: Option<Token>,
    /// Shell command run with `%s` replaced by the hash of every new
    /// main-chain tip, or `None`. For pools that prefer a hook to long
    /// polling.
    pub block_notify: Option<String>,
    /// Inbound connections accepted at once.
    pub max_inbound: usize,
}

impl Config {
    /// Validates loopback listeners, Tor settings, and onion-only peers.
    ///
    /// # Errors
    /// [`crate::Error::Argument`] describing the conflict.
    pub fn validate(&self) -> crate::Result<()> {
        for (name, addr) in [("control RPC", self.rpc), ("HTTP RPC", self.rpc_http)] {
            if addr.is_some_and(|addr| addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)) {
                return Err(crate::Error::Argument(format!(
                    "{name} must bind to 127.0.0.1"
                )));
            }
        }
        self.tor.validate()?;
        let inbound_capacity = self
            .max_inbound
            .checked_add(crate::net::MAX_PENDING_INBOUND);
        if inbound_capacity.is_none_or(|capacity| capacity > tokio::sync::Semaphore::MAX_PERMITS) {
            return Err(crate::Error::Argument(
                "maximum inbound peers exceeds the supported admission capacity".into(),
            ));
        }
        for endpoint in self.connect.iter().chain(&self.addnode) {
            crate::tor::validate_endpoint(endpoint)?;
        }
        Ok(())
    }

    /// A test node with no sockets and a temporary on-disk chain store.
    pub fn test() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_DATADIR: AtomicU64 = AtomicU64::new(0);
        let datadir = std::env::temp_dir().join(format!(
            "rhombus-node-test-{}-{}",
            std::process::id(),
            NEXT_TEST_DATADIR.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            network: Network::Test,
            datadir,
            cleanup_datadir: true,
            offline: true,
            p2p: false,
            connect: Vec::new(),
            addnode: Vec::new(),
            no_seeds: true,
            max_outbound: OUTBOUND_TARGET,
            tor: TorConfig::default(),
            mine_to: None,
            mining_threads: 1,
            rpc: None,
            rpc_http: None,
            rpc_token: None,
            block_notify: None,
            max_inbound: DEFAULT_MAX_INBOUND,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_network_is_recognized_by_its_genesis_hash() {
        for network in Network::ALL {
            let hash = genesis(&network.params()).hash();
            assert_eq!(Network::for_genesis(&hash), Some(network));
        }
        assert_eq!(Network::for_genesis(&BlockHash::ZERO), None);
    }

    #[test]
    fn networks_parse_and_print_by_name() {
        for network in Network::ALL {
            assert_eq!(network.to_string().parse::<Network>(), Ok(network));
        }
        assert!("other".parse::<Network>().is_err());
    }

    #[test]
    fn neither_network_has_builtin_seed_peers() {
        assert!(Network::ALL
            .iter()
            .all(|network| network.seeds().is_empty()));
    }

    #[test]
    fn the_test_network_has_no_public_seeds() {
        assert_eq!(Network::Test.seeds().len(), 0);
    }

    #[test]
    fn every_listener_must_bind_ipv4_loopback() {
        for rejected in [
            "0.0.0.0:19000",
            "8.8.8.8:19000",
            "[::1]:19000",
            "127.0.0.2:19000",
        ] {
            let addr = rejected.parse().unwrap();
            for field in 0..2 {
                let mut config = Config::test();
                match field {
                    0 => config.rpc = Some(addr),
                    _ => config.rpc_http = Some(addr),
                }
                assert!(config.validate().is_err(), "{rejected}, field {field}");
            }
        }
        let mut config = Config::test();
        let addr = "127.0.0.1:0".parse().unwrap();
        config.rpc = Some(addr);
        config.rpc_http = Some(addr);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn inbound_limit_cannot_overflow_admission_capacity() {
        let mut config = Config::test();
        config.max_inbound = usize::MAX;
        assert!(config.validate().is_err());
        config.max_inbound = tokio::sync::Semaphore::MAX_PERMITS;
        assert!(config.validate().is_err());
        config.max_inbound = tokio::sync::Semaphore::MAX_PERMITS
            .checked_sub(crate::net::MAX_PENDING_INBOUND)
            .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn configuration_refuses_non_onion_peers_and_zero_virtual_port() {
        let mut config = Config::test();
        for endpoint in ["127.0.0.1:19000", "example.org:19000", "abc.onion:19000"] {
            config.connect = vec![endpoint.into()];
            assert!(config.validate().is_err(), "{endpoint}");
        }
        config.connect = vec![p2p::address::NetAddr::TorV3([4; 32]).endpoint(19000)];
        assert!(config.validate().is_ok());
        config.tor.p2p_port = 0;
        assert!(config.validate().is_err());
    }
}
