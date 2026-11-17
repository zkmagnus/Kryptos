//! Repeatable block-relay measurements. Memory transport results are not Tor benchmarks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use chain::pow::RandomXPow;
use crypto::keys::SpendingKey;
use p2p::address::NetAddr;
use p2p::transport::{self, Incoming, Stream, TorNetwork};
use protocol::address::RhombusAddress;
use protocol::block::Block;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::{Config, DEFAULT_P2P_PORT};
use runtime::metrics::Metrics;
use runtime::miner::Template;
use runtime::node::{self, Handle, Request, Response, Submission};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;

const FRAME_DELAY: Duration = Duration::from_millis(75);
const SAMPLES: usize = 4;

/// Every frame on both directions of an accepted connection receives a fixed
/// delay. This tests application framing/relay/validation without public Tor.
fn delayed_network(
    identity: NetAddr,
    delay: Duration,
) -> (Arc<TorNetwork>, mpsc::Receiver<Incoming>, JoinHandle<()>) {
    let (network, mut incoming) = transport::test_support::network(identity, &[DEFAULT_P2P_PORT]);
    let (forward, received) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        let mut bridges = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = bridges.join_next(), if !bridges.is_empty() => {},
                next = incoming.recv() => {
                    let Some(Incoming {port, stream}) = next else { break; };
                    let (application, relay) = tokio::io::duplex(64 * 1024);
                    if forward.send(Incoming {port, stream: Stream::Memory(application)}).await.is_err() {
                        break;
                    }
                    bridges.spawn(async move {
                        let (mut outside_write, mut outside_read) = transport::split(stream);
                        let (mut inside_write, mut inside_read) = transport::split(Stream::Memory(relay));
                        let inward = async {
                            while let Ok(message) = outside_read.recv().await {
                                tokio::time::sleep(delay).await;
                                if inside_write.send(&message).await.is_err() { break; }
                            }
                        };
                        let outward = async {
                            while let Ok(message) = inside_read.recv().await {
                                tokio::time::sleep(delay).await;
                                if outside_write.send(&message).await.is_err() { break; }
                            }
                        };
                        tokio::select! { () = inward => {}, () = outward => {} }
                    });
                }
            }
        }
    });
    (network, received, task)
}

async fn template(node: &Handle) -> Template {
    let (reply, response) = oneshot::channel();
    node.events()
        .send(node::Event::TemplateRequest(reply))
        .await
        .unwrap();
    response.await.unwrap().unwrap()
}

async fn metrics(node: &Handle) -> Metrics {
    let Response::Metrics(metrics) = node.request(Request::Metrics).await.unwrap() else {
        panic!("expected metrics");
    };
    *metrics
}

async fn submit(node: &Handle, block: Block) -> Submission {
    let Response::BlockSubmitted(result) = node
        .request(Request::SubmitBlock(Box::new(block)))
        .await
        .unwrap()
    else {
        panic!("expected block submission");
    };
    result
}

async fn solve(
    template: Template,
    key: Arc<ProvingKey>,
    payout: RhombusAddress,
    seed: u64,
) -> Block {
    tokio::task::spawn_blocking(move || {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let pow = RandomXPow::new(template.params.randomx_key).unwrap();
        let (mut header, transactions) = template.assemble(&payout, &key, &mut rng).unwrap();
        assert!(pow.mine(&mut header, 100_000, &mut rng).unwrap());
        Block::new(header, transactions)
    })
    .await
    .unwrap()
}

fn payout() -> RhombusAddress {
    let mut rng = ChaCha20Rng::seed_from_u64(902);
    WalletKeys::from_spending_key(SpendingKey::random(&mut rng))
        .unwrap()
        .default_address()
        .unwrap()
}

async fn proving_key() -> Arc<ProvingKey> {
    Arc::new(
        tokio::task::spawn_blocking(|| ProvingKey::build().unwrap())
            .await
            .unwrap(),
    )
}

async fn ready_peer(node: &Handle) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if metrics(node).await.peers_outbound > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an outbound application handshake must complete");
}

async fn accepted_after(node: &Handle, hash: protocol::block::BlockHash, start: Instant) -> u64 {
    let mut tip = node.tip();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if *tip.borrow_and_update() == hash {
                return u64::try_from(start.elapsed().as_micros()).unwrap();
            }
            tip.changed().await.unwrap();
        }
    })
    .await
    .expect("block must propagate to the follower")
}

fn summary(samples: &[u64]) -> Value {
    let mut values = samples.to_vec();
    values.sort_unstable();
    let percentile = |percent: usize| values[(values.len() * percent).div_ceil(100) - 1];
    json!({
        "samples_us": samples,
        "count": values.len(),
        "p50_us": percentile(50),
        "p90_us": percentile(90),
        "p95_us": percentile(95),
        "max_us": values.last().unwrap()
    })
}

/// Four blocks traverse a fixed A -> B -> C chain with 75ms per application frame.
/// End-to-end times use one process's monotonic clock and include source validation.
#[allow(clippy::too_many_lines)] // One sequential experiment shares topology and measurements.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_three_node_relay_reports_timings() {
    let first_id = NetAddr::TorV3([221; 32]);
    let second_id = NetAddr::TorV3([222; 32]);
    let third_id = NetAddr::TorV3([223; 32]);
    let (first_net, source_incoming, first_bridge) = delayed_network(first_id, FRAME_DELAY);
    let (second_net, middle_incoming, second_bridge) = delayed_network(second_id, FRAME_DELAY);
    let (third_net, last_incoming, third_bridge) = delayed_network(third_id, FRAME_DELAY);
    let first = node::spawn_with_network(
        Config {
            offline: false,
            p2p: true,
            bootstrap_mining: true,
            mining_ready_secs: 0,
            max_outbound: 0,
            ..Config::test()
        },
        first_net,
        source_incoming,
    )
    .await
    .unwrap();
    let second = node::spawn_with_network(
        Config {
            offline: false,
            p2p: true,
            connect: vec![first_id.endpoint(DEFAULT_P2P_PORT)],
            mining_ready_secs: 0,
            max_outbound: 1,
            ..Config::test()
        },
        second_net,
        middle_incoming,
    )
    .await
    .unwrap();
    let third = node::spawn_with_network(
        Config {
            offline: false,
            p2p: true,
            connect: vec![second_id.endpoint(DEFAULT_P2P_PORT)],
            mining_ready_secs: 0,
            max_outbound: 1,
            ..Config::test()
        },
        third_net,
        last_incoming,
    )
    .await
    .unwrap();
    ready_peer(&second).await;
    ready_peer(&third).await;
    let key = proving_key().await;
    let payout = payout();
    let mut first_hop = Vec::new();
    let mut second_hop = Vec::new();
    for sample in 0..SAMPLES {
        let block = solve(
            template(&first).await,
            Arc::clone(&key),
            payout.clone(),
            sample as u64 + 901,
        )
        .await;
        let hash = block.hash();
        let start = Instant::now();
        assert_eq!(submit(&first, block).await, Submission::Accepted);
        let (b, c) = tokio::join!(
            accepted_after(&second, hash, start),
            accepted_after(&third, hash, start)
        );
        first_hop.push(b);
        second_hop.push(c);
        assert!(b >= u64::try_from(FRAME_DELAY.as_micros()).unwrap());
        assert!(c >= 2 * u64::try_from(FRAME_DELAY.as_micros()).unwrap());
    }
    let sender_metrics = metrics(&first).await;
    let second_metrics = metrics(&second).await;
    let third_metrics = metrics(&third).await;
    assert_eq!(sender_metrics.blocks_mined, SAMPLES);
    assert_eq!(sender_metrics.blocks_mined_stale, 0);
    assert_eq!(
        second_metrics.block_timing.first_seen_to_import.count,
        SAMPLES as u64
    );
    assert_eq!(
        third_metrics.block_timing.first_seen_to_import.count,
        SAMPLES as u64
    );
    assert_eq!(third_metrics.block_timing.validation.count, SAMPLES as u64);
    let report = json!({
        "measurement": "source_submission_to_follower_tip",
        "transport": "memory_with_fixed_frame_delay",
        "topology": "A -> B -> C",
        "frame_delay_us": FRAME_DELAY.as_micros(),
        "mainnet_target_seconds": runtime::config::Network::Main.params().block_interval,
        "test_network_target_seconds": runtime::config::Network::Test.params().block_interval,
        "sample_block_contents": "one coinbase transaction; no user transactions",
        "architecture": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "first_hop": summary(&first_hop),
        "second_hop": summary(&second_hop),
        "valid_local_blocks": sender_metrics.blocks_mined,
        "stale_local_blocks": sender_metrics.blocks_mined_stale,
        "competing_miners": false,
        "public_tor": false,
        "limitations": "Four sequential blocks and no competing miners. Includes source validation. Does not establish real Tor propagation or stale rate under contention."
    });
    println!(
        "PROPAGATION_REPORT {}",
        serde_json::to_string(&report).unwrap()
    );
    if let Ok(path) = std::env::var("RHOMBUS_PROPAGATION_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    third.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
    first_bridge.abort();
    second_bridge.abort();
    third_bridge.abort();
}

/// Distinct local solutions count even when first imported directly onto a side
/// chain, and the stale membership changes correctly when that branch wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_side_branches_and_reorgs_are_counted_without_duplicates() {
    let first = node::spawn(Config::test()).await.unwrap();
    let alternate = node::spawn(Config::test()).await.unwrap();
    let key = proving_key().await;
    let payout = payout();
    let base = template(&first).await;
    let a = solve(base.clone(), Arc::clone(&key), payout.clone(), 910).await;
    let b = solve(base, Arc::clone(&key), payout.clone(), 911).await;
    assert_ne!(a.hash(), b.hash());
    assert_eq!(submit(&first, a.clone()).await, Submission::Accepted);
    assert_eq!(submit(&alternate, b.clone()).await, Submission::Accepted);
    assert_eq!(submit(&first, b.clone()).await, Submission::Stale);
    let direct_stale = metrics(&first).await;
    assert_eq!(direct_stale.blocks_mined, 2);
    assert_eq!(direct_stale.blocks_mined_in_chain, 1);
    assert_eq!(direct_stale.blocks_mined_stale, 1);
    assert!(matches!(
        submit(&first, b).await,
        Submission::Duplicate | Submission::Stale
    ));
    assert_eq!(metrics(&first).await.blocks_mined, 2);
    let extension = solve(template(&alternate).await, key, payout, 912).await;
    assert_eq!(
        submit(&first, extension.clone()).await,
        Submission::Accepted
    );
    let reorganized = metrics(&first).await;
    assert_eq!(reorganized.blocks_mined, 3);
    assert_eq!(reorganized.blocks_mined_in_chain, 2);
    assert_eq!(reorganized.blocks_mined_stale, 1);
    assert_eq!(reorganized.blocks_mined_rejected, 0);
    assert_eq!(*first.tip().borrow(), extension.hash());
    let mut invalid_header = extension.header().clone();
    invalid_header.target = 0;
    let invalid = Block::new(invalid_header, extension.transactions().to_vec());
    assert!(matches!(
        submit(&first, invalid).await,
        Submission::Rejected(_)
    ));
    let rejected = metrics(&first).await;
    assert_eq!(rejected.blocks_mined_rejected, 1);
    assert_eq!(rejected.blocks_mined, 3);
    assert_eq!(rejected.blocks_mined_stale, 1);
    first.shutdown().await;
    alternate.shutdown().await;
}

async fn service_ready(network: &TorNetwork) {
    let mut status = network.status();
    while !network.ready() {
        status.changed().await.unwrap();
    }
}

/// An explicit public-Tor experiment. Both nodes run on this machine, so these
/// observations cannot substitute for a geographically distributed campaign.
#[allow(clippy::too_many_lines)] // Bootstrap, measurement and teardown form one experiment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires public Tor, two onion-service bootstraps and block proofs"]
async fn public_tor_two_node_relay_reports_timings() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let (first_net, source_incoming) =
        TorNetwork::start(first_dir.path(), true, &[DEFAULT_P2P_PORT]).unwrap();
    let (second_net, middle_incoming) =
        TorNetwork::start(second_dir.path(), true, &[DEFAULT_P2P_PORT]).unwrap();
    tokio::time::timeout(Duration::from_mins(25), async {
        tokio::join!(service_ready(&first_net), service_ready(&second_net));
    })
    .await
    .expect("both public onion services must become ready");
    let first_id = first_net.status().borrow().onion.unwrap();
    let first = node::spawn_with_network(
        Config {
            datadir: first_dir.path().to_path_buf(),
            cleanup_datadir: false,
            offline: false,
            p2p: true,
            bootstrap_mining: true,
            mining_ready_secs: 0,
            max_outbound: 0,
            ..Config::test()
        },
        first_net,
        source_incoming,
    )
    .await
    .unwrap();
    let second = node::spawn_with_network(
        Config {
            datadir: second_dir.path().to_path_buf(),
            cleanup_datadir: false,
            offline: false,
            p2p: true,
            connect: vec![first_id.endpoint(DEFAULT_P2P_PORT)],
            mining_ready_secs: 0,
            max_outbound: 1,
            ..Config::test()
        },
        second_net,
        middle_incoming,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if metrics(&second).await.peers_outbound > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("application handshake over public Tor");
    let key = proving_key().await;
    let payout = payout();
    let samples: usize = std::env::var("RHOMBUS_PROPAGATION_SAMPLES").map_or(SAMPLES, |value| {
        value.parse().expect("sample count must be an integer")
    });
    assert!((1..=100).contains(&samples), "use 1..=100 samples per run");
    let mut timings = Vec::new();
    for index in 0..samples {
        let block = solve(
            template(&first).await,
            Arc::clone(&key),
            payout.clone(),
            1_000 + index as u64,
        )
        .await;
        let hash = block.hash();
        let start = Instant::now();
        assert_eq!(submit(&first, block).await, Submission::Accepted);
        timings.push(accepted_after(&second, hash, start).await);
    }
    let measured = metrics(&first).await;
    let report = json!({
        "measurement": "source_submission_to_follower_tip",
        "transport": "public_tor_same_host",
        "topology": "A -> B",
        "mainnet_target_seconds": runtime::config::Network::Main.params().block_interval,
        "test_network_target_seconds": runtime::config::Network::Test.params().block_interval,
        "sample_block_contents": "one coinbase transaction; no user transactions",
        "architecture": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "first_hop": summary(&timings),
        "valid_local_blocks": measured.blocks_mined,
        "stale_local_blocks": measured.blocks_mined_stale,
        "competing_miners": false,
        "public_tor": true,
        "limitations": "Both nodes run on one machine; sequential blocks without competing miners. Includes source validation. Results do not establish network-wide or majority-hashrate latency, or stale rate under contention."
    });
    println!(
        "PROPAGATION_REPORT {}",
        serde_json::to_string(&report).unwrap()
    );
    if let Ok(path) = std::env::var("RHOMBUS_PROPAGATION_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    second.shutdown().await;
    first.shutdown().await;
}
