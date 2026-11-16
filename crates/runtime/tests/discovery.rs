//! Onion reachability and peer exchange through memory stream fixtures.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

mod common;
use common::{ScriptedService, TorFixture};
use p2p::addrbook::Snapshot;
use p2p::address::NetAddr;
use p2p::message::{Message, PeerAddr};
use p2p::peer::{version_info, Direction};
use p2p::transport::{split, ConnectionReader, ConnectionWriter};
use runtime::config::{Config, OUTBOUND_TARGET};
use runtime::node::{Event, Handle, PeerSummary, Request, Response};

const DEADLINE: Duration = Duration::from_secs(30);
/// Ticks between a node's address exchanges (`discovery::EXCHANGE_SECONDS`).
const EXCHANGE_TICKS: usize = 600;
/// Ticks before a node answers the same peer's `GetAddr` again
/// (`discovery::REPLY_SECONDS`).
const REPLY_TICKS: usize = 60;

async fn peers(node: &Handle) -> Vec<PeerSummary> {
    match node.request(Request::Peers).await.unwrap() {
        Response::Peers(peers) => peers,
        other => panic!("unexpected {other:?}"),
    }
}

async fn tick(nodes: &[&Handle], times: usize) {
    for _ in 0..times {
        for node in nodes {
            node.events().send(Event::Tick).await.unwrap();
        }
    }
}

async fn wait_for(nodes: &[&Handle], mut check: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !check().await {
            for node in nodes {
                node.events().send(Event::Tick).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

fn address(addr: NetAddr) -> PeerAddr {
    PeerAddr::new(addr, runtime::config::DEFAULT_P2P_PORT, runtime::now())
}

struct Client {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

impl Client {
    async fn connect(network: &TorFixture, node: &Handle) -> Self {
        let genesis = match node.request(Request::Block(0)).await.unwrap() {
            Response::Block(Some(block)) => block.hash(),
            other => panic!("unexpected {other:?}"),
        };
        let stream = network.connect(&network.endpoint(node)).await.unwrap();
        let (writer, reader) = split(stream);
        let mut client = Self { writer, reader };
        client
            .writer
            .send(&Message::Version(version_info(
                123,
                0,
                genesis,
                runtime::now(),
            )))
            .await
            .unwrap();
        let mut version = false;
        let mut verack = false;
        while !version || !verack {
            match client.recv().await {
                Message::Version(_) => {
                    version = true;
                    client.writer.send(&Message::Verack).await.unwrap();
                }
                Message::Verack => verack = true,
                other => panic!("unexpected handshake message {other:?}"),
            }
        }
        client.barrier().await;
        client
    }

    async fn recv(&mut self) -> Message {
        let message = tokio::time::timeout(DEADLINE, self.reader.recv())
            .await
            .unwrap()
            .unwrap();
        match &message {
            Message::GetAddr => self.writer.send(&Message::Addr(Vec::new())).await.unwrap(),
            Message::Ping(nonce) => self.writer.send(&Message::Pong(*nonce)).await.unwrap(),
            _ => {}
        }
        message
    }

    /// Drain preceding messages and wait until the node processed our writes.
    async fn barrier(&mut self) {
        self.writer.send(&Message::Ping(456)).await.unwrap();
        while self.recv().await != Message::Pong(456) {}
    }

    /// Asks for addresses and returns the next address list received.
    async fn get_addr(&mut self) -> Vec<PeerAddr> {
        self.writer.send(&Message::GetAddr).await.unwrap();
        loop {
            if let Message::Addr(addrs) = self.recv().await {
                return addrs;
            }
        }
    }

    async fn wait_for_address(&mut self, addr: NetAddr) {
        let expected = address(addr).key();
        tokio::time::timeout(DEADLINE, async {
            loop {
                if let Message::Addr(addrs) = self.recv().await {
                    if addrs.iter().any(|a| a.key() == expected) {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_discovers_a_listener_that_joins_its_seed_later() {
    let network = TorFixture::new();
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let seed_target = network.endpoint(&seed);
    let wallet = network
        .spawn(Config {
            connect: vec![seed_target.clone()],
            ..Config::test()
        })
        .await;
    wait_for(&[&wallet], async || {
        peers(&wallet).await.iter().any(|p| p.ready)
    })
    .await;
    let newcomer = network
        .spawn(Config {
            p2p: true,
            connect: vec![seed_target],
            ..Config::test()
        })
        .await;
    let newcomer_addr = address(newcomer.onion_addr.unwrap()).key();
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .any(|p| p.ready && p.addr == Some(newcomer_addr))
    })
    .await;
    // Verified addresses are pulled, never pushed: the wallet learns the
    // newcomer at its next exchange with the seed.
    tick(&[&seed, &wallet], EXCHANGE_TICKS).await;
    wait_for(&[&seed, &wallet], async || {
        peers(&wallet)
            .await
            .iter()
            .any(|p| p.ready && p.addr == Some(newcomer_addr))
    })
    .await;
    newcomer.shutdown().await;
    wallet.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_seed_verifies_and_relays_a_new_inbound_listening_node() {
    let network = TorFixture::new();
    let mut bootstrap = Vec::new();
    for _ in 0..OUTBOUND_TARGET {
        bootstrap.push(
            network
                .spawn(Config {
                    p2p: true,
                    ..Config::test()
                })
                .await,
        );
    }
    let seed = network
        .spawn(Config {
            p2p: true,
            connect: bootstrap.iter().map(|n| network.endpoint(n)).collect(),
            ..Config::test()
        })
        .await;
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .filter(|p| p.ready && p.direction == Direction::Outbound)
            .count()
            == OUTBOUND_TARGET
    })
    .await;
    let mut observer = Client::connect(&network, &seed).await;
    let newcomer = network
        .spawn(Config {
            p2p: true,
            connect: vec![network.endpoint(&seed)],
            ..Config::test()
        })
        .await;
    let expected = address(newcomer.onion_addr.unwrap()).key();
    tokio::time::timeout(DEADLINE, async {
        while !observer
            .get_addr()
            .await
            .iter()
            .any(|a| a.key() == expected)
        {
            tick(&[&seed], REPLY_TICKS).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        peers(&seed)
            .await
            .iter()
            .filter(|p| p.ready && p.direction == Direction::Outbound)
            .count(),
        OUTBOUND_TARGET
    );
    newcomer.shutdown().await;
    seed.shutdown().await;
    for node in bootstrap {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepting_a_stream_without_a_network_handshake_does_not_make_an_address_gossipable() {
    let network = TorFixture::new();
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let mut sender = Client::connect(&network, &seed).await;
    let mut observer = Client::connect(&network, &seed).await;
    let mut silent = ScriptedService::new();
    let silent_identity = silent.identity;
    sender
        .writer
        .send(&Message::Addr(vec![address(silent_identity)]))
        .await
        .unwrap();
    sender.barrier().await;
    for _ in 0..5 {
        seed.events().send(Event::Tick).await.unwrap();
    }
    let (_socket, ()) = tokio::time::timeout(DEADLINE, silent.accept())
        .await
        .unwrap()
        .unwrap();
    observer.writer.send(&Message::GetAddr).await.unwrap();
    loop {
        if let Message::Addr(sample) = observer.recv().await {
            assert!(sample.is_empty(), "an unverified address was relayed");
            break;
        }
    }
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfinished_version_handshake_cannot_start_chain_sync() {
    let network = TorFixture::new();
    let mut server = ScriptedService::new();
    let identity = server.identity;
    let node = network
        .spawn(Config {
            connect: vec![identity.endpoint(runtime::config::DEFAULT_P2P_PORT)],
            ..Config::test()
        })
        .await;
    let (stream, ()) = server.accept().await.unwrap();
    let (mut writer, mut reader) = split(stream);
    let Message::Version(ours) = reader.recv().await.unwrap() else {
        panic!("expected version");
    };
    writer
        .send(&Message::Version(version_info(
            123,
            1,
            ours.genesis,
            runtime::now(),
        )))
        .await
        .unwrap();
    // Receiving our Verack proves the node processed the version. The
    // remote side deliberately never acknowledges it, so it is not ready.
    assert_eq!(reader.recv().await.unwrap(), Message::Verack);
    node.events().send(Event::Tick).await.unwrap();
    let Response::Status { syncing, .. } = node.request(Request::Status).await.unwrap() else {
        panic!("expected status");
    };
    assert!(!syncing, "a peer still being verified was used for sync");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn established_peers_repeat_announcements_but_ask_only_outbound_peers_for_addresses() {
    let network = TorFixture::new();
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let mut observer = Client::connect(&network, &seed).await;
    tick(&[&seed], EXCHANGE_TICKS).await;
    observer.writer.send(&Message::Ping(789)).await.unwrap();
    let expected = address(seed.onion_addr.unwrap()).key();
    let mut announcement = false;
    loop {
        match observer.recv().await {
            Message::Addr(addrs) => announcement |= addrs.iter().any(|a| a.key() == expected),
            Message::GetAddr => panic!("an inbound peer was asked for addresses"),
            Message::Pong(789) => break,
            _ => {}
        }
    }
    assert!(announcement, "the listener was not announced again");
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inbound_peer_can_only_announce_one_address_per_exchange() {
    let network = TorFixture::new();
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let mut sender = Client::connect(&network, &seed).await;
    let mut first = ScriptedService::new();
    let mut second = ScriptedService::new();
    let first_identity = first.identity;
    let second_identity = second.identity;
    let flood = [first_identity, second_identity, second_identity]
        .map(address)
        .to_vec();
    sender.writer.send(&Message::Addr(flood)).await.unwrap();
    sender.barrier().await;
    tick(&[&seed], REPLY_TICKS).await;
    tokio::time::timeout(DEADLINE, first.accept())
        .await
        .unwrap()
        .unwrap();
    tick(&[&seed], REPLY_TICKS).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), second.accept())
            .await
            .is_err(),
        "an address beyond the inbound allowance was dialed"
    );
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_onion_service_identity_and_virtual_port_are_shared() {
    let network = TorFixture::new();
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let node = network
        .spawn(Config {
            p2p: true,
            connect: vec![network.endpoint(&seed)],
            ..Config::test()
        })
        .await;
    let identity = node.onion_addr.unwrap();
    let expected = address(identity).key();
    wait_for(&[&seed], async || {
        peers(&seed)
            .await
            .iter()
            .any(|peer| peer.ready && peer.addr == Some(expected))
    })
    .await;
    let mut observer = Client::connect(&network, &seed).await;
    observer.writer.send(&Message::GetAddr).await.unwrap();
    observer.wait_for_address(identity).await;
    assert_eq!(expected.1, runtime::config::DEFAULT_P2P_PORT);
    node.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_node_reconnects_saved_anchors_and_shares_verified_services() {
    let network = TorFixture::new();
    let dir = tempfile::tempdir().unwrap();
    let listening = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let target = listening.onion_addr.unwrap();
    let node = network
        .spawn(Config {
            datadir: dir.path().to_path_buf(),
            cleanup_datadir: false,
            connect: vec![target.endpoint(runtime::config::DEFAULT_P2P_PORT)],
            ..Config::test()
        })
        .await;
    wait_for(&[&node], async || {
        peers(&node)
            .await
            .iter()
            .any(|p| p.ready && p.addr == Some(address(target).key()))
    })
    .await;
    node.shutdown().await;

    let saved =
        Snapshot::from_bytes(&std::fs::read(dir.path().join("peers.dat")).unwrap()).unwrap();
    let entry = saved
        .entries()
        .iter()
        .find(|s| s.addr.key() == address(target).key());
    assert!(entry.unwrap().verified_at.is_some(), "saved as verified");

    // The empty configured-peer list must reconnect through the saved anchor.
    // Its persisted verification was also checked directly above.
    let restarted = network
        .spawn(Config {
            datadir: dir.path().to_path_buf(),
            cleanup_datadir: false,
            p2p: true,
            ..Config::test()
        })
        .await;
    wait_for(&[&restarted], async || {
        peers(&restarted)
            .await
            .iter()
            .any(|peer| peer.ready && peer.addr == Some(address(target).key()))
    })
    .await;
    let mut client = Client::connect(&network, &restarted).await;
    let shared = client.get_addr().await;
    assert!(
        shared.iter().any(|a| a.key() == address(target).key()),
        "{shared:?}"
    );
    restarted.shutdown().await;
    listening.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outbound_only_restart_starts_tor_for_saved_anchors() {
    let network = TorFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let listening = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let target = listening.onion_addr.unwrap();
    let node = network
        .spawn(Config {
            datadir: directory.path().to_path_buf(),
            cleanup_datadir: false,
            connect: vec![network.endpoint(&listening)],
            ..Config::test()
        })
        .await;
    wait_for(&[&node], async || {
        peers(&node)
            .await
            .iter()
            .any(|peer| peer.ready && peer.addr == Some(address(target).key()))
    })
    .await;
    node.shutdown().await;

    // No listener or configured peer remains to activate Tor. Persisted
    // anchors alone must enable readiness monitoring and the isolated dial.
    let restarted = network
        .spawn(Config {
            datadir: directory.path().to_path_buf(),
            cleanup_datadir: false,
            ..Config::test()
        })
        .await;
    assert!(restarted.onion_addr.is_some());
    wait_for(&[&restarted], async || {
        peers(&restarted)
            .await
            .iter()
            .any(|peer| peer.ready && peer.addr == Some(address(target).key()))
    })
    .await;
    restarted.shutdown().await;
    listening.shutdown().await;
}
