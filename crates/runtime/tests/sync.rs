//! Two in-process nodes: a miner and a follower that syncs from it, then
//! a payment submitted to the follower is relayed and mined by the miner.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::{Duration, Instant};

use common::TorFixture;
use crypto::keys::SpendingKey;
use protocol::amount::RawCoin;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::{Config, Network};
use runtime::node::{Handle, Request, Response};
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;
use wallet::spend::{build_payment, Payment};
use wallet::wallet::Wallet;

async fn height(handle: &Handle) -> u32 {
    match handle.request(Request::Status).await.unwrap() {
        Response::Status { height, .. } => height,
        other => panic!("unexpected {other:?}"),
    }
}

async fn wait_for(deadline: Duration, mut check: impl AsyncFnMut() -> bool) {
    let started = Instant::now();
    while !check().await {
        assert!(started.elapsed() < deadline, "timed out");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_syncs_from_miner_and_relays_a_payment() {
    let network = TorFixture::new();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let miner_sk = SpendingKey::random(&mut rng);
    let miner_keys = WalletKeys::from_spending_key(miner_sk.clone()).unwrap();
    let miner_address = miner_keys.default_address().unwrap();
    let receiver = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let test_dir = tempfile::tempdir().unwrap();

    let miner = network
        .spawn(Config {
            datadir: test_dir.path().join("miner"),
            cleanup_datadir: false,
            p2p: true,
            mine_to: Some(miner_address),
            max_inbound: 125,
            ..Config::test()
        })
        .await;
    let follower = network
        .spawn(Config {
            datadir: test_dir.path().join("follower"),
            cleanup_datadir: false,
            connect: vec![network.endpoint(&miner)],
            max_inbound: 125,
            ..Config::test()
        })
        .await;

    // The follower catches up with the miner.
    // The first reward is spendable once block 1 is in the tree.
    let spendable = common::first_spendable_height().max(2);
    wait_for(Duration::from_secs(240), async || {
        height(&follower).await >= spendable
    })
    .await;
    let miner_height = height(&miner).await;
    assert!(miner_height >= spendable);

    // Scan the miner's chain as its wallet and pay the receiver through
    // the follower, which relays to the miner.
    let scanned_to = height(&miner).await;
    let Response::Block(Some(genesis)) = miner.request(Request::Block(0)).await.unwrap() else {
        panic!("genesis")
    };
    let wallet = Wallet::create(
        test_dir.path().join("wallet.redb"),
        &miner_sk,
        genesis.hash(),
        &mut rng,
    )
    .unwrap();
    common::scan_chain(&miner, &wallet, scanned_to).await;
    assert!(
        wallet.balance().unwrap() > 0,
        "the miner earned coinbase notes"
    );
    let pk = ProvingKey::build().unwrap();
    let payment = Payment {
        recipient: receiver.default_address().unwrap(),
        amount: RawCoin::from_raw(1_000).unwrap(),
    };
    // The test network schedules no upgrades, so the genesis branch is in
    // force at every height.
    let branch = Network::Test.params().branch_at(height(&miner).await + 1);
    let tx = build_payment(&wallet, payment, &pk, branch, &mut rng).unwrap();
    let nullifier = *tx.actions()[0].body().nullifier();
    let Response::Submitted(_) = follower
        .request(Request::Submit(Box::new(tx)))
        .await
        .unwrap()
    else {
        panic!("submit")
    };

    // The miner eventually includes it: one of its nullifiers is spent.
    wait_for(Duration::from_secs(120), async || {
        matches!(
            miner.request(Request::IsSpent(nullifier)).await.unwrap(),
            Response::Spent(true)
        )
    })
    .await;
    // And the follower sees the same chain.
    wait_for(Duration::from_secs(60), async || {
        matches!(
            follower.request(Request::IsSpent(nullifier)).await.unwrap(),
            Response::Spent(true)
        )
    })
    .await;

    follower.shutdown().await;
    miner.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_connections_are_capped() {
    let network = TorFixture::new();
    let node = network
        .spawn(Config {
            p2p: true,
            max_inbound: 2,
            ..Config::test()
        })
        .await;
    let addr = network.endpoint(&node);
    let genesis = node_genesis(&node).await;
    // Complete the application handshake for two healthy peers. A third
    // connection must not evict them merely by opening another onion stream.
    let mut versions = 0;
    let mut kept = Vec::new();
    for attempt in 0..3u64 {
        let stream = network.connect(&addr).await.unwrap();
        let (mut writer, mut reader) = p2p::transport::split(stream);
        let hello = p2p::message::Message::Version(p2p::peer::version_info(7, 0, genesis, 0));
        if writer.send(&hello).await.is_err() {
            continue;
        }
        let got = tokio::time::timeout(Duration::from_secs(2), reader.recv()).await;
        if matches!(got, Ok(Ok(p2p::message::Message::Version(_)))) {
            versions += 1;
            writer
                .send(&p2p::message::Message::Ping(attempt))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while reader.recv().await.unwrap() != p2p::message::Message::Pong(attempt) {}
            })
            .await
            .unwrap();
            kept.push((writer, reader));
        }
    }
    assert_eq!(versions, 2);
    drop(kept);
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_incomplete_inbound_handshake_is_evicted_before_a_healthy_peer() {
    use p2p::message::Message;
    let network = TorFixture::new();
    let node = network
        .spawn(Config {
            p2p: true,
            max_inbound: 1,
            ..Config::test()
        })
        .await;
    let endpoint = network.endpoint(&node);
    let silent = network.connect(&endpoint).await.unwrap();
    let (_silent_writer, mut silent_reader) = p2p::transport::split(silent);
    // A node request acts as an actor barrier after the connection is admitted.
    wait_for(Duration::from_secs(10), async || {
        matches!(node.request(Request::Peers).await.unwrap(), Response::Peers(peers) if peers.len() == 1)
    })
    .await;
    let stream = network.connect(&endpoint).await.unwrap();
    let (mut writer, mut reader) = p2p::transport::split(stream);
    writer
        .send(&Message::Version(p2p::peer::version_info(
            19,
            0,
            node_genesis(&node).await,
            0,
        )))
        .await
        .unwrap();
    assert!(matches!(reader.recv().await.unwrap(), Message::Version(_)));
    writer.send(&Message::Ping(88)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while reader.recv().await.unwrap() != Message::Pong(88) {}
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), silent_reader.recv())
            .await
            .unwrap()
            .is_err()
    );
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("peers")
    };
    assert_eq!(peers.len(), 1);
    assert!(peers.first().unwrap().ready);
    node.shutdown().await;
}

async fn node_genesis(node: &Handle) -> protocol::block::BlockHash {
    match node.request(Request::Block(0)).await.unwrap() {
        Response::Block(Some(block)) => block.hash(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_resumes_its_chain_after_a_restart() {
    let network = TorFixture::new();
    let dir = tempfile::tempdir().unwrap();
    let miner_keys =
        WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(9)))
            .unwrap();
    let config = Config {
        datadir: dir.path().to_path_buf(),
        cleanup_datadir: false,
        mine_to: Some(miner_keys.default_address().unwrap()),
        ..Config::test()
    };
    let node = network.spawn(config.clone()).await;
    wait_for(Duration::from_secs(120), async || height(&node).await >= 2).await;
    let tip = match node.request(Request::Status).await.unwrap() {
        Response::Status { height, hash, .. } => (height, hash),
        other => panic!("unexpected {other:?}"),
    };
    node.shutdown().await;

    let reopened = network
        .spawn(Config {
            mine_to: None,
            cleanup_datadir: false,
            ..config
        })
        .await;
    let after = match reopened.request(Request::Status).await.unwrap() {
        Response::Status { height, hash, .. } => (height, hash),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(after, tip, "the chain survives a restart intact");
    reopened.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_snapshot_reports_mined_blocks_and_the_status_line_counts_them() {
    let network = TorFixture::new();
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let miner = network
        .spawn(Config {
            mine_to: Some(keys.default_address().unwrap()),
            ..Config::test()
        })
        .await;
    wait_for(Duration::from_secs(120), async || height(&miner).await >= 2).await;

    let (found, in_chain) = match miner.request(Request::Status).await.unwrap() {
        Response::Status {
            mined,
            mined_in_chain,
            ..
        } => (mined, mined_in_chain),
        other => panic!("unexpected {other:?}"),
    };
    assert!(found >= 2);
    assert_eq!(found, in_chain, "a lone miner has no stale blocks");

    let Response::Metrics(metrics) = miner.request(Request::Metrics).await.unwrap() else {
        panic!("metrics")
    };
    let body = runtime::metrics::render(&metrics);
    assert!(body.contains("blocks_mined{state=\"found\"} "));
    assert!(body.contains("height "));
    assert!(body.contains("uptime_seconds "));
    miner.shutdown().await;
}

async fn peer_count(handle: &Handle) -> usize {
    match handle.request(Request::Status).await.unwrap() {
        Response::Status { peers, .. } => peers,
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_discovers_a_peer_it_was_never_configured_with() {
    let network = TorFixture::new();
    // A listens. B connects to A and listens, so it learns A's address.
    // C connects only to B and must reach A through gossiped addresses.
    let seed = network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await;
    let seed_addr = network.endpoint(&seed);

    let relay = network
        .spawn(Config {
            p2p: true,
            connect: vec![seed_addr.clone()],
            ..Config::test()
        })
        .await;
    let relay_addr = network.endpoint(&relay);

    let far = network
        .spawn(Config {
            connect: vec![relay_addr],
            ..Config::test()
        })
        .await;

    // C starts with one configured peer (B) and must find a second (A).
    wait_for(Duration::from_secs(60), async || {
        peer_count(&far).await >= 2
    })
    .await;
    assert!(
        peer_count(&far).await >= 2,
        "the far node reached a peer it was never given"
    );

    far.shutdown().await;
    relay.shutdown().await;
    seed.shutdown().await;
}
