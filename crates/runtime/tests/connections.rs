//! Connection collision and identity-spoofing regressions over memory onion streams.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use chain::genesis::genesis;
use chain::params::ChainParams;
use p2p::address::NetAddr;
use p2p::message::Message;
use p2p::peer::{version_info, Direction};
use p2p::transport::{split, test_support, ConnectionReader, ConnectionWriter};
use runtime::config::{Config, DEFAULT_P2P_PORT};
use runtime::node::{spawn_with_network, Handle, PeerSummary, Request, Response};

const DEADLINE: Duration = Duration::from_secs(30);

async fn peers(node: &Handle) -> Vec<PeerSummary> {
    match tokio::time::timeout(DEADLINE, node.request(Request::Peers))
        .await
        .expect("node stopped responding")
        .unwrap()
    {
        Response::Peers(peers) => peers,
        other => panic!("unexpected peers response: {other:?}"),
    }
}

async fn wait_for(mut predicate: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !predicate().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("connection state did not converge");
}

async fn receive(reader: &mut ConnectionReader) -> Message {
    tokio::time::timeout(DEADLINE, reader.recv())
        .await
        .expect("peer read timed out")
        .unwrap()
}

async fn send(writer: &mut ConnectionWriter, message: Message) {
    tokio::time::timeout(DEADLINE, writer.send(&message))
        .await
        .expect("peer write timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_dials_converge_to_one_stable_lower_onion_outbound() {
    let lower = NetAddr::TorV3([61; 32]);
    let higher = NetAddr::TorV3([62; 32]);
    // Register both destinations before either actor starts, so both configured
    // dials succeed even when startup futures are scheduled in different orders.
    let (lower_network, lower_incoming) = test_support::network(lower, &[DEFAULT_P2P_PORT]);
    let (higher_network, higher_incoming) = test_support::network(higher, &[DEFAULT_P2P_PORT]);
    let (lower_node, higher_node) = tokio::join!(
        spawn_with_network(
            Config {
                p2p: true,
                max_outbound: 1,
                connect: vec![higher.endpoint(DEFAULT_P2P_PORT)],
                ..Config::test()
            },
            lower_network,
            lower_incoming,
        ),
        spawn_with_network(
            Config {
                p2p: true,
                max_outbound: 1,
                connect: vec![lower.endpoint(DEFAULT_P2P_PORT)],
                ..Config::test()
            },
            higher_network,
            higher_incoming,
        ),
    );
    let lower_node = lower_node.unwrap();
    let higher_node = higher_node.unwrap();
    wait_for(async || {
        let lower_peers = peers(&lower_node).await;
        let higher_peers = peers(&higher_node).await;
        matches!(lower_peers.as_slice(), [peer] if peer.ready && peer.direction == Direction::Outbound && peer.addr == Some((higher, DEFAULT_P2P_PORT)))
            && matches!(higher_peers.as_slice(), [peer] if peer.ready && peer.direction == Direction::Inbound && peer.addr == Some((lower, DEFAULT_P2P_PORT)))
    })
    .await;
    let lower_id = peers(&lower_node).await.first().unwrap().id;
    let higher_id = peers(&higher_node).await.first().unwrap().id;
    // Observe at least one five-second pool-maintenance tick. The linked inbound
    // occupies the maintained slot and must not cause another reverse dial.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(6) {
        for (node, id) in [(&lower_node, lower_id), (&higher_node, higher_id)] {
            let connected = peers(node).await;
            assert!(matches!(connected.as_slice(), [peer] if peer.id == id && peer.ready));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let lower_peers = peers(&lower_node).await;
    let measured = lower_peers.first().unwrap();
    assert!(measured.connect_millis.is_some());
    assert!(measured.received_bytes > 0);
    assert!(measured.sent_bytes > 0);
    assert!(measured.bytes_per_second > 0);
    higher_node.shutdown().await;
    lower_node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_inbound_onion_and_link_cannot_evict_the_authenticated_outbound() {
    let remote = NetAddr::TorV3([71; 32]);
    let local = NetAddr::TorV3([72; 32]);
    let attacker = NetAddr::TorV3([73; 32]);
    let (remote_network, mut remote_incoming) = test_support::network(remote, &[DEFAULT_P2P_PORT]);
    let (local_network, local_incoming) = test_support::network(local, &[DEFAULT_P2P_PORT]);
    let (attacker_network, _attacker_incoming) = test_support::network(attacker, &[]);
    let node = spawn_with_network(
        Config {
            p2p: true,
            max_outbound: 1,
            connect: vec![remote.endpoint(DEFAULT_P2P_PORT)],
            ..Config::test()
        },
        local_network,
        local_incoming,
    )
    .await
    .unwrap();
    let genuine_stream = tokio::time::timeout(DEADLINE, remote_incoming.recv())
        .await
        .unwrap()
        .unwrap()
        .stream;
    let (mut genuine_writer, mut genuine_reader) = split(genuine_stream);
    let Message::Version(challenge) = receive(&mut genuine_reader).await else {
        panic!("expected outgoing version")
    };
    let genesis = genesis(&ChainParams::test()).hash();
    let mut genuine_version = version_info(101, 0, genesis, runtime::now());
    genuine_version.onion = Some((remote, DEFAULT_P2P_PORT));
    send(&mut genuine_writer, Message::Version(genuine_version)).await;
    wait_for(async || matches!(peers(&node).await.as_slice(), [peer] if peer.ready)).await;
    let genuine_id = peers(&node).await.first().unwrap().id;

    let forged_stream = attacker_network
        .connect(&local.endpoint(DEFAULT_P2P_PORT))
        .await
        .unwrap();
    let (mut forged_writer, mut forged_reader) = split(forged_stream);
    let mut forged_version = version_info(202, 0, genesis, runtime::now());
    forged_version.onion = Some((remote, DEFAULT_P2P_PORT));
    send(&mut forged_writer, Message::Version(forged_version)).await;
    let Message::Version(reply) = receive(&mut forged_reader).await else {
        panic!("expected inbound version response")
    };
    assert_ne!(
        reply.nonce, challenge.nonce,
        "an inbound claim must not expose the outgoing nonce"
    );
    // Try both the nonce the attacker supplied and the unrelated nonce received
    // in its own handshake. Neither proves receipt by the real remote onion.
    send(&mut forged_writer, Message::ConnectionLink(202)).await;
    send(&mut forged_writer, Message::ConnectionLink(reply.nonce)).await;
    send(&mut forged_writer, Message::Ping(303)).await;
    loop {
        match receive(&mut forged_reader).await {
            Message::Pong(303) => break,
            Message::Ping(nonce) => send(&mut forged_writer, Message::Pong(nonce)).await,
            Message::ConnectionLink(nonce) => {
                assert_ne!(
                    nonce, challenge.nonce,
                    "outbound nonce leaked to a claimed inbound identity"
                );
            }
            _ => {}
        }
    }
    let connected = peers(&node).await;
    assert_eq!(connected.len(), 2);
    let genuine = connected.iter().find(|peer| peer.id == genuine_id).unwrap();
    assert_eq!(genuine.direction, Direction::Outbound);
    assert_eq!(genuine.addr, Some((remote, DEFAULT_P2P_PORT)));
    assert!(genuine.ready);
    let forged = connected.iter().find(|peer| peer.id != genuine_id).unwrap();
    assert_eq!(forged.direction, Direction::Inbound);
    assert_eq!(
        forged.addr, None,
        "a claimed onion is not an authenticated identity"
    );
    // The inbound token is sent only to the authenticated remote destination.
    loop {
        match receive(&mut genuine_reader).await {
            Message::ConnectionLink(202) => break,
            Message::Ping(nonce) => send(&mut genuine_writer, Message::Pong(nonce)).await,
            _ => {}
        }
    }
    drop(remote_network);
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_early_reverse_link_waits_for_the_outbound_version_before_collapsing() {
    let remote = NetAddr::TorV3([81; 32]);
    let local = NetAddr::TorV3([82; 32]);
    let (remote_network, mut remote_incoming) = test_support::network(remote, &[DEFAULT_P2P_PORT]);
    let (local_network, local_incoming) = test_support::network(local, &[DEFAULT_P2P_PORT]);
    let node = spawn_with_network(
        Config {
            p2p: true,
            max_outbound: 1,
            connect: vec![remote.endpoint(DEFAULT_P2P_PORT)],
            ..Config::test()
        },
        local_network,
        local_incoming,
    )
    .await
    .unwrap();
    let outbound = tokio::time::timeout(DEADLINE, remote_incoming.recv())
        .await
        .unwrap()
        .unwrap()
        .stream;
    let (mut outbound_writer, mut outbound_reader) = split(outbound);
    let Message::Version(challenge) = receive(&mut outbound_reader).await else {
        panic!("expected outgoing version")
    };
    // Independently scheduled streams may deliver the reverse link before the
    // reply to the node's outgoing Version. Delay that reply deliberately.
    let reverse = remote_network
        .connect(&local.endpoint(DEFAULT_P2P_PORT))
        .await
        .unwrap();
    let (mut reverse_writer, mut reverse_reader) = split(reverse);
    let genesis = genesis(&ChainParams::test()).hash();
    let mut reverse_version = version_info(401, 0, genesis, runtime::now());
    reverse_version.onion = Some((remote, DEFAULT_P2P_PORT));
    send(&mut reverse_writer, Message::Version(reverse_version)).await;
    assert!(matches!(
        receive(&mut reverse_reader).await,
        Message::Version(_)
    ));
    send(
        &mut reverse_writer,
        Message::ConnectionLink(challenge.nonce),
    )
    .await;
    send(&mut reverse_writer, Message::Ping(402)).await;
    loop {
        match receive(&mut reverse_reader).await {
            Message::Pong(402) => break,
            Message::Ping(nonce) => send(&mut reverse_writer, Message::Pong(nonce)).await,
            _ => {}
        }
    }
    // The pong proves the actor processed the link. It must keep the candidate
    // unbound until the authenticated destination passes the network handshake.
    let before_reply = peers(&node).await;
    assert_eq!(before_reply.len(), 2);
    let inbound = before_reply
        .iter()
        .find(|peer| peer.direction == Direction::Inbound)
        .unwrap();
    assert!(inbound.ready);
    assert_eq!(inbound.addr, None);
    let inbound_id = inbound.id;
    assert!(before_reply
        .iter()
        .any(|peer| peer.direction == Direction::Outbound && !peer.ready));

    let mut reply = version_info(403, 0, genesis, runtime::now());
    reply.onion = Some((remote, DEFAULT_P2P_PORT));
    send(&mut outbound_writer, Message::Version(reply)).await;
    wait_for(async || {
        matches!(peers(&node).await.as_slice(), [peer]
            if peer.id == inbound_id && peer.ready && peer.direction == Direction::Inbound
                && peer.addr == Some((remote, DEFAULT_P2P_PORT)))
    })
    .await;
    node.shutdown().await;
}
