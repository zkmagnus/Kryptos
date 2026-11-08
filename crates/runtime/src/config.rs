//! Node configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use chain::genesis::genesis;
use chain::params::ChainParams;
use protocol::address::{AddressPrefix, RhombusAddress};
use protocol::block::BlockHash;

use crate::rpc::Token;

/// Outbound connections the node tries to keep.
pub const OUTBOUND_TARGET: usize = 8;
/// Transactions the mempool holds.
pub const MEMPOOL_CAPACITY: usize = 10_000;
/// Inbound connections accepted at once, by default.
pub const DEFAULT_MAX_INBOUND: usize = 125;

/// Conventional port for node operators who want a fixed P2P listener port.
pub const DEFAULT_P2P_PORT: u16 = 19000;

/// Which network to join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Provisional main network parameters.
    Main,
    /// Separate RandomX key and short block interval for local testing.
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

    /// Built-in bootstrap peers, as `host:port`. Rhombus has none configured;
    /// pass `--seed` or `--connect` to use a custom peer.
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
pub struct Config {
    /// The network.
    pub network: Network,
    /// Directory holding the persistent chain database and peer book.
    pub datadir: PathBuf,
    /// Remove this directory when a test node shuts down.
    pub cleanup_datadir: bool,
    /// Address to accept peers on, or `None` to only dial out.
    pub listen: Option<SocketAddr>,
    /// Public listening IP and port to announce, for example a NAT mapping.
    /// Without an override, direct public listen/interface addresses are used.
    /// Requires a listener and is incompatible with proxy operation.
    pub advertise: Option<SocketAddr>,
    /// Peers to dial at startup, as `host:port`; hostnames are resolved,
    /// or handed to the proxy when one is set, so `.onion` names work.
    pub connect: Vec<String>,
    /// SOCKS5 proxy for every outbound connection, such as Tor's
    /// `127.0.0.1:9050`. Inbound connections are unaffected.
    pub proxy: Option<SocketAddr>,
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
    /// Prometheus metrics endpoint, or `None` for none.
    pub metrics: Option<SocketAddr>,
    /// Inbound connections accepted at once.
    pub max_inbound: usize,
}

impl Config {
    /// Checks combinations of settings that a front end's own parsing may
    /// not catch, such as `advertise` from a configuration file.
    ///
    /// # Errors
    /// [`crate::Error::Argument`] describing the conflict.
    pub fn validate(&self) -> crate::Result<()> {
        crate::discovery::validate(self)
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
            listen: None,
            advertise: None,
            connect: Vec::new(),
            proxy: None,
            mine_to: None,
            mining_threads: 1,
            rpc: None,
            rpc_http: None,
            rpc_token: None,
            block_notify: None,
            metrics: None,
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
}
