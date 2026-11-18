//! Mining readiness policy tests for online Tor nodes.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ScriptedService, TorFixture};
use p2p::address::NetAddr;
use p2p::message::Message;
use p2p::peer::version_info;
use p2p::transport::{split, test_support, ConnectionReader, ConnectionWriter};
use runtime::config::{Config, DEFAULT_P2P_PORT};
use runtime::node::{spawn_with_network, Handle, NotReady, Request, Response};
use tokio::time::sleep;

async fn readiness(node: &Handle) -> Option<NotReady> {
    match node.request(Request::MiningReadiness).await.unwrap() {
        Response::MiningReadiness(reason) => reason,
        other => panic!("unexpected response: {other:?}"),
    }
}

async fn wait_readiness(node: &Handle, expected: Option<NotReady>) {
    let started = Instant::now();
    loop {
        if readiness(node).await == expected {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "mining readiness did not become {expected:?}; got {:?}",
            readiness(node).await
        );
        sleep(Duration::from_millis(25)).await;
    }
}

fn online(config: Config) -> Config {
    Config {
        offline: false,
        p2p: true,
        mining_min_peers: 1,
        mining_ready_secs: 0,
        ..config
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_mining_waits_for_an_outbound_peer() {
    let fixture = TorFixture::new();
    let node = fixture.spawn(online(Config::test())).await;

    wait_readiness(&node, Some(NotReady::NoPeers)).await;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_only_connectivity_does_not_unlock_mining() {
    let fixture = TorFixture::new();
    let node = fixture.spawn(online(Config::test())).await;
    let endpoint = fixture.endpoint(&node);
    let genesis = match node.request(Request::Block(0)).await.unwrap() {
        Response::Block(Some(block)) => block.hash(),
        other => panic!("unexpected genesis response: {other:?}"),
    };

    // Complete an inbound application handshake. The policy requires an
    // authenticated outbound peer, so this connection alone is insufficient.
    let stream = fixture.connect(&endpoint).await.unwrap();
    let (mut writer, mut reader) = split(stream);
    writer
        .send(&Message::Version(version_info(7, 0, genesis, 0)))
        .await
        .unwrap();
    assert!(matches!(reader.recv().await.unwrap(), Message::Version(_)));
    writer.send(&Message::Ping(19)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match reader.recv().await.unwrap() {
                Message::Pong(19) => break,
                Message::GetHeaders { .. } => {
                    writer.send(&Message::Headers(Vec::new())).await.unwrap();
                }
                _ => {}
            }
        }
    })
    .await
    .expect("inbound handshake must complete");
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("expected peer list");
    };
    assert!(peers.iter().any(|peer| peer.ready));
    wait_readiness(&node, Some(NotReady::NoPeers)).await;
    drop((writer, reader));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_mode_allows_the_first_node_to_mine_without_a_peer() {
    let fixture = TorFixture::new();
    let node = fixture
        .spawn(online(Config {
            bootstrap_mining: true,
            ..Config::test()
        }))
        .await;

    // Bootstrap mode is explicit: it bypasses the outbound-peer requirement
    // while retaining Tor readiness and any sync checks.
    wait_readiness(&node, None).await;
    node.shutdown().await;
}

struct RemotePeer {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

impl RemotePeer {
    async fn accept(service: &mut ScriptedService, height: u32) -> Self {
        let (stream, ()) = tokio::time::timeout(Duration::from_secs(15), service.accept())
            .await
            .expect("node must dial its configured peer")
            .unwrap();
        Self::handshake(stream, height).await
    }

    async fn handshake(stream: p2p::transport::Stream, height: u32) -> Self {
        let (writer, reader) = split(stream);
        let mut peer = Self { writer, reader };
        let Message::Version(node_version) = peer.next().await else {
            panic!("outbound node must send Version");
        };
        peer.send(Message::Version(version_info(
            node_version.nonce.wrapping_add(1),
            height,
            node_version.genesis,
            runtime::now(),
        )))
        .await;
        peer
    }

    async fn next(&mut self) -> Message {
        tokio::time::timeout(Duration::from_secs(10), self.reader.recv())
            .await
            .expect("peer message deadline")
            .unwrap()
    }

    async fn send(&mut self, message: Message) {
        self.writer.send(&message).await.unwrap();
    }

    async fn until_headers_request(&mut self) {
        loop {
            match self.next().await {
                Message::GetHeaders { .. } => return,
                Message::Ping(nonce) => self.send(Message::Pong(nonce)).await,
                _ => {}
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equal_height_outbound_peer_requires_sync_and_reconnect_requires_a_new_check() {
    let fixture = TorFixture::new();
    let mut service = ScriptedService::new();
    let mut config = online(Config {
        connect: vec![service.identity.endpoint(DEFAULT_P2P_PORT)],
        ..Config::test()
    });
    // Exercise reconnect readiness without waiting the production backoff.
    config.tor.settings.retry_initial = Duration::from_secs(1);
    config.tor.settings.retry_max = Duration::from_secs(2);
    let node = fixture.spawn(config).await;
    let mut remote = RemotePeer::accept(&mut service, 0).await;
    remote.until_headers_request().await;
    wait_readiness(&node, Some(NotReady::Syncing)).await;

    remote.send(Message::Headers(Vec::new())).await;
    wait_readiness(&node, None).await;
    drop(remote);
    wait_readiness(&node, Some(NotReady::NoPeers)).await;

    let mut reconnected = RemotePeer::accept(&mut service, 0).await;
    reconnected.until_headers_request().await;
    wait_readiness(&node, Some(NotReady::Syncing)).await;
    reconnected.send(Message::Headers(Vec::new())).await;
    wait_readiness(&node, None).await;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_still_waits_for_tor_and_stable_recovery() {
    let (network, incoming) = test_support::network(NetAddr::TorV3([219; 32]), &[DEFAULT_P2P_PORT]);
    test_support::set_ready(&network, false);
    let node = spawn_with_network(
        Config {
            offline: false,
            p2p: true,
            bootstrap_mining: true,
            mining_ready_secs: 1,
            ..Config::test()
        },
        Arc::clone(&network),
        incoming,
    )
    .await
    .unwrap();
    wait_readiness(&node, Some(NotReady::TorUnavailable)).await;

    test_support::set_ready(&network, true);
    wait_readiness(&node, Some(NotReady::Stabilizing)).await;
    sleep(Duration::from_millis(250)).await;
    assert_eq!(readiness(&node).await, Some(NotReady::Stabilizing));
    wait_readiness(&node, None).await;

    test_support::set_ready(&network, false);
    wait_readiness(&node, Some(NotReady::TorUnavailable)).await;
    test_support::set_ready(&network, true);
    wait_readiness(&node, Some(NotReady::Stabilizing)).await;
    sleep(Duration::from_millis(250)).await;
    assert_eq!(readiness(&node).await, Some(NotReady::Stabilizing));
    wait_readiness(&node, None).await;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfulfilled_higher_tip_claim_cannot_count_as_a_synced_peer() {
    let fixture = TorFixture::new();
    let mut service = ScriptedService::new();
    let node = fixture
        .spawn(online(Config {
            connect: vec![service.identity.endpoint(DEFAULT_P2P_PORT)],
            ..Config::test()
        }))
        .await;
    let mut remote = RemotePeer::accept(&mut service, 1).await;
    remote.until_headers_request().await;
    remote.send(Message::Headers(Vec::new())).await;
    remote.send(Message::Ping(28)).await;
    loop {
        if remote.next().await == Message::Pong(28) {
            break;
        }
    }
    // Empty headers do not establish that the advertised chain was downloaded.
    assert!(readiness(&node).await.is_some());
    assert!(matches!(
        node.request(Request::Status).await.unwrap(),
        Response::Status { height: 0, .. }
    ));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_submissions_are_blocked_before_import_when_online_node_has_no_peers() {
    let fixture = TorFixture::new();
    let node = fixture.spawn(online(Config::test())).await;
    wait_readiness(&node, Some(NotReady::NoPeers)).await;
    let Response::Block(Some(genesis)) = node.request(Request::Block(0)).await.unwrap() else {
        panic!("expected genesis");
    };
    // Even a known valid block takes the readiness rejection path, rather
    // than bypassing policy through an external miner's submit endpoint.
    let response = node.request(Request::SubmitBlock(genesis)).await.unwrap();
    assert!(matches!(
        response,
        Response::BlockSubmitted(runtime::node::Submission::Rejected(_))
    ));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_ports_of_one_onion_identity_do_not_satisfy_two_peer_minimum() {
    let fixture = TorFixture::new();
    let identity = NetAddr::TorV3([220; 32]);
    let (_network, mut incoming) = test_support::network(identity, &[19000, 19001]);
    // Different virtual ports authenticate the same onion identity. The dialer
    // keeps one connection, which must not satisfy a two-identity minimum.
    let node = fixture
        .spawn(Config {
            offline: false,
            p2p: true,
            mining_min_peers: 2,
            mining_ready_secs: 0,
            connect: vec![identity.endpoint(19000), identity.endpoint(19001)],
            ..Config::test()
        })
        .await;
    let first = tokio::time::timeout(Duration::from_secs(10), incoming.recv())
        .await
        .expect("configured peer must connect")
        .unwrap();
    let mut remote = RemotePeer::handshake(first.stream, 0).await;
    remote.until_headers_request().await;
    remote.send(Message::Headers(Vec::new())).await;
    remote.send(Message::Ping(220)).await;
    loop {
        if remote.next().await == Message::Pong(220) {
            break;
        }
    }
    // Cover a five-second connection-maintenance tick: the alternate port
    // must not open a second connection after the first finishes syncing.
    assert!(
        tokio::time::timeout(Duration::from_secs(6), incoming.recv())
            .await
            .is_err()
    );
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("expected peer list");
    };
    assert_eq!(peers.len(), 1);
    assert!(peers[0].ready);
    assert_eq!(readiness(&node).await, Some(NotReady::NoPeers));
    drop(remote);
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_required_outbound_identity_must_complete_initial_sync() {
    let fixture = TorFixture::new();
    let mut first_service = ScriptedService::new();
    let mut second_service = ScriptedService::new();
    let node = fixture
        .spawn(Config {
            offline: false,
            p2p: true,
            mining_min_peers: 2,
            mining_ready_secs: 0,
            connect: vec![
                first_service.identity.endpoint(DEFAULT_P2P_PORT),
                second_service.identity.endpoint(DEFAULT_P2P_PORT),
            ],
            ..Config::test()
        })
        .await;
    let mut first = RemotePeer::accept(&mut first_service, 0).await;
    first.until_headers_request().await;
    first.send(Message::Headers(Vec::new())).await;
    wait_readiness(&node, Some(NotReady::NoPeers)).await;

    let mut second = RemotePeer::accept(&mut second_service, 0).await;
    second.until_headers_request().await;
    wait_readiness(&node, Some(NotReady::Syncing)).await;
    second.send(Message::Headers(Vec::new())).await;
    wait_readiness(&node, None).await;
    drop(first);
    wait_readiness(&node, Some(NotReady::NoPeers)).await;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_does_not_treat_absent_online_transport_as_offline_permission() {
    let node = runtime::node::spawn(Config {
        offline: false,
        p2p: false,
        bootstrap_mining: true,
        mining_ready_secs: 0,
        ..Config::test()
    })
    .await
    .unwrap();
    assert_eq!(readiness(&node).await, Some(NotReady::TorUnavailable));
    node.shutdown().await;
}
