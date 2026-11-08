//! The built-in miner can be started and stopped while the node runs, as
//! the desktop's mining switch does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use crypto::keys::SpendingKey;
use node::config::{Config, Network};
use node::miner;
use node::node::{spawn, Handle, Request, Response};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use wallet::keys::WalletKeys;

/// Blocks this node mined, and how many are in its main chain.
async fn mined(node: &Handle) -> (usize, usize) {
    match node.request(Request::Metrics).await.unwrap() {
        Response::Metrics(m) => (m.blocks_mined, m.blocks_mined_in_chain),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_miner_started_at_runtime_mines_and_stops_cleanly() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let payout = keys.default_address().unwrap();
    let node = spawn(Config::test()).await.unwrap();
    assert_eq!(mined(&node).await, (0, 0), "nothing mines until started");

    let tip = node.tip();
    let genesis = *tip.borrow();
    let running = miner::start(payout, Network::Test.params(), 2, node.events(), node.tip());
    assert_eq!((running.payout, running.threads), (payout, 2));
    tokio::time::timeout(Duration::from_secs(300), async {
        while mined(&node).await.1 == 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("a block within five minutes on the test network");

    assert_ne!(*tip.borrow(), genesis, "the tip watch follows mined blocks");
    running.stop().await.unwrap();
    let after_stop = mined(&node).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(mined(&node).await, after_stop, "no blocks after stop");
    node.shutdown().await;
}
