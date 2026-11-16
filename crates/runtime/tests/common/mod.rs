//! Helpers shared by the node integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use runtime::node::{Handle, Request, Response};
use wallet::wallet::Wallet;

use p2p::address::NetAddr;
use p2p::transport::{Incoming, Stream, TorNetwork};
use runtime::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// An explicit memory-only onion network for application integration tests.
pub struct TorFixture {
    client: Arc<TorNetwork>,
    identities: Mutex<HashMap<PathBuf, NetAddr>>,
    ports: Mutex<HashMap<NetAddr, u16>>,
}

fn identity() -> NetAddr {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut key = [0u8; 32];
    key.get_mut(..8)
        .unwrap()
        .copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    NetAddr::TorV3(key)
}

impl TorFixture {
    pub fn new() -> Self {
        Self {
            client: p2p::transport::test_support::network(identity(), &[]).0,
            identities: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashMap::new()),
        }
    }

    pub async fn connect(&self, endpoint: &str) -> p2p::Result<Stream> {
        self.client.connect(endpoint).await
    }

    /// Preserves mock service identity across restarts of the same data directory.
    pub async fn spawn(&self, config: Config) -> Handle {
        let identity = *self
            .identities
            .lock()
            .unwrap()
            .entry(config.datadir.clone())
            .or_insert_with(identity);
        self.ports
            .lock()
            .unwrap()
            .insert(identity, config.tor.p2p_port);
        let ports = if config.p2p {
            vec![config.tor.p2p_port]
        } else {
            Vec::new()
        };
        let (network, incoming) = p2p::transport::test_support::network(identity, &ports);
        runtime::node::spawn_with_network(config, network, incoming)
            .await
            .unwrap()
    }

    pub fn endpoint(&self, node: &Handle) -> String {
        let identity = node.onion_addr.unwrap();
        let port = self.ports.lock().unwrap().get(&identity).copied().unwrap();
        identity.endpoint(port)
    }
}

/// Scripted service consuming only memory streams, with no operating-system socket.
pub struct ScriptedService {
    _network: Arc<TorNetwork>,
    incoming: tokio::sync::mpsc::Receiver<Incoming>,
    pub identity: NetAddr,
}

impl ScriptedService {
    pub fn new() -> Self {
        let identity = identity();
        let (network, incoming) =
            p2p::transport::test_support::network(identity, &[runtime::config::DEFAULT_P2P_PORT]);
        Self {
            _network: network,
            incoming,
            identity,
        }
    }

    pub async fn accept(&mut self) -> Option<(Stream, ())> {
        self.incoming
            .recv()
            .await
            .map(|incoming| (incoming.stream, ()))
    }
}

/// A reward mined at height 1 is in the tree after block 1 and spendable
/// from block 2 onward.
pub fn first_spendable_height() -> u32 {
    1
}

/// Scans `node`'s chain from genesis to `to` into `wallet`.
pub async fn scan_chain(node: &Handle, wallet: &Wallet, to: u32) {
    for h in 0..=to {
        let Response::Block(Some(block)) = node.request(Request::Block(h)).await.unwrap() else {
            panic!("block {h}")
        };
        wallet.scan(&block).unwrap();
    }
}
