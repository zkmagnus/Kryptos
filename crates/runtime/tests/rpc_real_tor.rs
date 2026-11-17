//! Explicit public-Tor RPC coverage, including recovery after server idle closure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../p2p/tests/support/arti_trace.rs"]
mod arti_trace;

use std::time::Duration;

use crypto::encoding::from_hex;
use crypto::keys::SpendingKey;
use p2p::transport::TorNetwork;
use protocol::block::BlockHash;
use protocol::bytes::Encodable;
use protocol::compact::CompactBlock;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::cli::sync_wallet;
use runtime::config::Config;
use runtime::node::spawn;
use runtime::rpc::{Client, Control, Token};
use wallet::wallet::Wallet;

/// Run explicitly with:
/// `cargo test -p runtime --test rpc_real_tor -- --ignored --nocapture`.
/// Creates only fresh temporary Tor state and a genesis-only test node.
#[test]
#[ignore = "requires public Tor relays and onion descriptor publication"]
fn real_tor_rpc_reads_reconnect_after_idle_and_reopen_cleanly() {
    arti_trace::init().unwrap();
    // Arti background tasks flush state when the runtime shuts down. Keep
    // both temporary directories alive until that shutdown has completed.
    let node_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(run_rpc_smoke(node_dir.path(), client_dir.path()));
    drop(runtime);
}

async fn run_rpc_smoke(node_dir: &std::path::Path, client_dir: &std::path::Path) {
    let token = Token::new("rpc-smoke-test-only").unwrap();
    let node = spawn(Config {
        datadir: node_dir.to_path_buf(),
        cleanup_datadir: false,
        offline: false,
        p2p: true,
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: Some(token.clone()),
        ..Config::test()
    })
    .await
    .unwrap();
    let (client_network, _incoming) = TorNetwork::start(client_dir, false, &[]).unwrap();
    let mut service_status = node.tor_status.clone().unwrap();
    eprintln!("RPC smoke: waiting for embedded Tor client and onion publication");
    let onion = tokio::time::timeout(Duration::from_mins(20), async {
        loop {
            let current = *service_status.borrow_and_update();
            if let Some(onion) = current.onion.filter(|_| current.client_ready) {
                break onion;
            }
            service_status.changed().await.unwrap();
        }
    })
    .await
    .expect("node onion service must publish within twenty minutes");
    client_network.wait_ready().await.unwrap();
    let endpoint = onion.endpoint(node.rpc_addr.unwrap().port());
    let mut client = Client::connect(&client_network, &endpoint, &token)
        .await
        .unwrap();
    assert!(client.call("status").await.unwrap().contains("height=0"));
    let genesis = client.call("hash 0").await.unwrap();
    let compact = client.call("compact 0").await.unwrap();
    assert_eq!(
        CompactBlock::from_slice(&from_hex(&compact).unwrap())
            .unwrap()
            .height,
        0
    );

    // Exercise the balance path: public snapshot download, explicit session
    // shutdown, then wallet scanning. The user wallet is never opened here.
    let mut rng = ChaCha20Rng::seed_from_u64(371);
    let spending_key = SpendingKey::random(&mut rng);
    let wallet = Wallet::create(
        client_dir.join("test-wallet.redb"),
        &spending_key,
        BlockHash::from_bytes(from_hex(&genesis).unwrap().try_into().unwrap()),
        &mut rng,
    )
    .unwrap();
    assert_eq!(sync_wallet(&mut client, &wallet, false).await.unwrap(), 0);
    assert_eq!(wallet.next_height().unwrap(), 1);
    assert_eq!(wallet.balance().unwrap(), 0);
    client.close().await.unwrap();
    client = Client::connect(&client_network, &endpoint, &token)
        .await
        .unwrap();
    // The already-synchronized light path must close cleanly as well.
    assert_eq!(sync_wallet(&mut client, &wallet, true).await.unwrap(), 0);
    assert_eq!(wallet.balance().unwrap(), 0);
    drop(wallet);
    client = Client::connect(&client_network, &endpoint, &token)
        .await
        .unwrap();
    assert_eq!(client.call("hash 0").await.unwrap(), genesis);

    // The server closes authenticated sessions after 30 seconds without a
    // request. The next read must reconnect and authenticate, not reuse a
    // closed Arti stream or expose its raw NotConnected error.
    eprintln!(
        "RPC smoke: balance full/light sync and close passed; waiting for server idle closure"
    );
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert_eq!(client.call("hash 0").await.unwrap(), genesis);
    client.close().await.unwrap();
    client.close().await.unwrap();
    let mut second = Client::connect(&client_network, &endpoint, &token)
        .await
        .unwrap();
    assert_eq!(second.call("hash 0").await.unwrap(), genesis);
    second.close().await.unwrap();
    drop(client);
    drop(second);
    drop(client_network);
    node.shutdown().await;
    eprintln!("RPC smoke: status/hash/compact, balance full/light sync, idle reconnect and fresh session passed");
}
