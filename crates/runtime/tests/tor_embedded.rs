//! Readiness regression coverage with in-memory Tor, plus an optional real-network test.
//! Run the real-network test explicitly with `cargo test -p runtime --test tor_embedded -- --ignored --nocapture`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../p2p/tests/support/arti_trace.rs"]
mod arti_trace;

use std::sync::Arc;
use std::time::Duration;

use chain::pow::RandomXPow;
use crypto::keys::SpendingKey;
use p2p::address::NetAddr;
use p2p::transport::{test_support, TorNetwork};
use protocol::block::Block;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::{Config, DEFAULT_P2P_PORT};
use runtime::miner::Template;
use runtime::node::{spawn_with_network, Event, Handle, NotReady, Request, Response};
use tokio::sync::oneshot;
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires public Tor connectivity and two onion service bootstraps"]
async fn two_embedded_nodes_connect_using_addnode_over_real_tor() {
    arti_trace::init().unwrap();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let (first_tor, first_incoming) =
        TorNetwork::start(first_dir.path(), true, &[DEFAULT_P2P_PORT]).unwrap();
    let (second_tor, second_incoming) =
        TorNetwork::start(second_dir.path(), true, &[DEFAULT_P2P_PORT]).unwrap();
    tokio::time::timeout(Duration::from_mins(15), async {
        tokio::join!(wait_for_service(&first_tor), wait_for_service(&second_tor));
    })
    .await
    .expect("both embedded onion services must become ready within fifteen minutes");
    let identity = first_tor.status().borrow().onion.unwrap();
    let first = spawn_with_network(
        Config {
            datadir: first_dir.path().to_path_buf(),
            cleanup_datadir: false,
            offline: false,
            p2p: true,
            ..Config::test()
        },
        first_tor,
        first_incoming,
    )
    .await
    .unwrap();
    let second = spawn_with_network(
        Config {
            datadir: second_dir.path().to_path_buf(),
            cleanup_datadir: false,
            offline: false,
            p2p: true,
            addnode: vec![identity.endpoint(DEFAULT_P2P_PORT)],
            ..Config::test()
        },
        second_tor,
        second_incoming,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let Response::Peers(peers) = second.request(Request::Peers).await.unwrap() else {
                panic!("expected peer list");
            };
            if peers
                .iter()
                .any(|peer| peer.ready && peer.addr == Some((identity, DEFAULT_P2P_PORT)))
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("the configured onion peer must complete the application handshake");
    second.shutdown().await;
    first.shutdown().await;
}

async fn wait_for_service(network: &TorNetwork) {
    let mut status = network.status();
    while !network.ready() {
        status
            .changed()
            .await
            .expect("Tor supervisor must remain running");
    }
}

/// A solution arriving after Tor went away must not extend an isolated chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mining_waits_for_tor_and_rejects_late_work_until_recovery() {
    let identity = NetAddr::TorV3([211; 32]);
    let (network, incoming) = test_support::network(identity, &[DEFAULT_P2P_PORT]);
    test_support::set_ready(&network, false);
    let node = spawn_with_network(
        Config {
            offline: false,
            p2p: true,
            bootstrap_mining: true,
            mining_ready_secs: 0,
            ..Config::test()
        },
        Arc::clone(&network),
        incoming,
    )
    .await
    .unwrap();

    wait_for_mining_readiness(&node, Some(NotReady::TorUnavailable)).await;
    assert_eq!(
        request_template(&node).await.unwrap_err(),
        NotReady::TorUnavailable
    );
    let Response::Metrics(metrics) = node.request(Request::Metrics).await.unwrap() else {
        panic!("expected metrics");
    };
    assert_eq!(metrics.mining_waits, Some(NotReady::TorUnavailable));
    assert_eq!(metrics.height, 0);

    test_support::set_ready(&network, true);
    wait_for_mining_readiness(&node, None).await;
    let template = request_template(&node).await.unwrap();
    let block = tokio::task::spawn_blocking(move || {
        let mut rng = ChaCha20Rng::seed_from_u64(211);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let payout = keys.default_address().unwrap();
        let key = ProvingKey::build().unwrap();
        let pow = RandomXPow::new(template.params.randomx_key).unwrap();
        let (mut header, transactions) = template.assemble(&payout, &key, &mut rng).unwrap();
        assert!(pow.mine(&mut header, 4096, &mut rng).unwrap());
        Block::new(header, transactions)
    })
    .await
    .unwrap();
    let hash = block.hash();

    test_support::set_ready(&network, false);
    wait_for_mining_readiness(&node, Some(NotReady::TorUnavailable)).await;
    assert_eq!(
        request_template(&node).await.unwrap_err(),
        NotReady::TorUnavailable
    );
    node.events()
        .send(Event::Mined(Box::new(block.clone())))
        .await
        .unwrap();
    // The request is queued after Mined, so this observes its completed handling.
    assert!(matches!(
        node.request(Request::BlockByHash(hash)).await.unwrap(),
        Response::Block(None)
    ));
    assert!(matches!(
        node.request(Request::Status).await.unwrap(),
        Response::Status {
            height: 0,
            mined: 0,
            ..
        }
    ));

    test_support::set_ready(&network, true);
    wait_for_mining_readiness(&node, None).await;
    assert!(request_template(&node).await.is_ok());
    // Accepting the very same solution after recovery proves it was valid work.
    node.events()
        .send(Event::Mined(Box::new(block)))
        .await
        .unwrap();
    assert!(matches!(
        node.request(Request::Status).await.unwrap(),
        Response::Status { height: 1, hash: tip, mined: 1, .. } if tip == hash
    ));
    node.shutdown().await;
}

async fn request_template(node: &Handle) -> Result<Template, NotReady> {
    let (reply, response) = oneshot::channel();
    node.events()
        .send(Event::TemplateRequest(reply))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("node must answer the template request")
        .unwrap()
}

async fn wait_for_mining_readiness(node: &Handle, expected: Option<NotReady>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let Response::MiningReadiness(actual) =
                node.request(Request::MiningReadiness).await.unwrap()
            else {
                panic!("expected mining readiness");
            };
            if actual == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mining readiness must follow Tor availability");
}
