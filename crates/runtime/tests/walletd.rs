//! The wallet daemon against a live mining node: sync, addresses with
//! labels, balances, a multi-recipient send carried from queued to
//! confirmed, transaction views, and operations.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chain::genesis::genesis;
use crypto::keys::SpendingKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::{Config, Network};
use runtime::jsonrpc::{NOT_FOUND, REJECTED};
use runtime::node::spawn;
use runtime::rpc::{Endpoint, Token};
use runtime::walletd;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wallet::keys::WalletKeys;
use wallet::wallet::Wallet;

async fn post(addr: SocketAddr, token: &str, body: &str) -> Value {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: wallet\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

async fn call(addr: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let reply = post(addr, token, &body.to_string()).await;
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

async fn call_err(addr: SocketAddr, token: &str, method: &str, params: Value) -> i64 {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let reply = post(addr, token, &body.to_string()).await;
    assert!(reply["result"].is_null(), "{method}: {reply}");
    reply["error"]["code"].as_i64().unwrap()
}

async fn wait_for(deadline: Duration, mut check: impl AsyncFnMut() -> bool) {
    let started = Instant::now();
    while !check().await {
        assert!(started.elapsed() < deadline, "timed out");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// One node, one daemon and one proving key serve every assertion, and
// the steps build on each other's chain state.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wallet_daemon_serves_an_exchange() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let miner_sk = SpendingKey::random(&mut rng);
    let miner_keys = WalletKeys::from_spending_key(miner_sk.clone()).unwrap();
    let customer = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
    let node_token = Token::new("node").unwrap();
    let node = spawn(Config {
        mine_to: Some(miner_keys.default_address().unwrap()),
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        rpc_token: Some(node_token.clone()),
        ..Config::test()
    })
    .await
    .unwrap();
    let genesis_hash = genesis(&Network::Test.params()).hash();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exchange.redb");
    drop(Wallet::create(&path, &miner_sk, genesis_hash, &mut rng).unwrap());
    let wallet = Wallet::open(&path, genesis_hash).unwrap();
    let token = Token::new("wallet").unwrap();
    let daemon = walletd::run(walletd::Config {
        wallet,
        network: Network::Test,
        node: Endpoint {
            addr: node.rpc_addr.unwrap().to_string(),
            token: node_token,
        },
        listen: "127.0.0.1:0".parse().unwrap(),
        token: token.clone(),
        sync_interval: Duration::from_millis(500),
        light: false,
    })
    .await
    .unwrap();
    let addr = daemon.addr;
    let t = token.expose();
    let prefix = Network::Test.address_prefix();

    // It syncs and sees the coinbase notes from blocks 1 to 3.
    let three_rewards = 3u64;
    wait_for(Duration::from_secs(240), async || {
        let info = call(addr, t, "getwalletinfo", json!([])).await;
        info["scanned_height"]
            .as_u64()
            .is_some_and(|h| h >= three_rewards)
    })
    .await;
    let info = call(addr, t, "getwalletinfo", json!([])).await;
    assert_eq!(info["network"], "test");
    assert!(info["unspent"].as_u64().unwrap() >= 3);
    let balance = call(addr, t, "getbalance", json!([1])).await;
    assert!(
        balance["spendable"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 2_000_000_000
    );
    let unspent = call(addr, t, "listunspent", json!([])).await;
    assert_eq!(unspent[0]["address_index"], 0);
    assert!(unspent[0]["txid"].is_string());
    assert_eq!(unspent[0]["memo"], Value::Null);

    // Deposit addresses with labels.
    let alice = call(addr, t, "getnewaddress", json!(["alice"])).await;
    assert_eq!(alice["index"], 1);
    let alice_address = alice["address"].as_str().unwrap().to_string();
    let bob = call(addr, t, "getnewaddress", json!({"label": "bob"})).await;
    assert_eq!(bob["index"], 2);
    let listed = call(addr, t, "listaddresses", json!([])).await;
    assert_eq!(listed.as_array().unwrap().len(), 3);
    assert_eq!(listed[1]["label"], "alice");
    let info = call(addr, t, "getaddressinfo", json!([alice_address])).await;
    assert_eq!(info["is_mine"], true);
    assert_eq!(info["label"], "alice");
    let customer_address = customer.default_address().unwrap().encode(prefix);
    assert_eq!(
        call(addr, t, "getaddressinfo", json!([customer_address])).await["is_mine"],
        false
    );
    assert_eq!(
        call(addr, t, "validateaddress", json!([customer_address])).await["valid"],
        true
    );
    assert_eq!(
        call(addr, t, "validateaddress", json!(["tnull1junk"])).await["valid"],
        false
    );

    // A withdrawal to the customer and a deposit to alice in one send.
    let sent = call(
        addr,
        t,
        "sendmany",
        json!([[
        {"address": customer_address, "amount": "1000", "memo": "withdrawal 1"},
        {"address": alice_address, "amount": 500},
    ], 1]),
    )
    .await;
    let id = sent["operation_id"].as_u64().unwrap();
    assert_eq!(sent["status"], "queued");
    wait_for(Duration::from_secs(180), async || {
        call(addr, t, "getoperationstatus", json!([id])).await["status"] == "confirmed"
    })
    .await;
    let op = call(addr, t, "getoperationstatus", json!([id])).await;
    let txid = op["txid"].as_str().unwrap().to_string();
    assert_eq!(op["total"], "1500");
    assert_eq!(op["attempts"], 1);
    assert!(op["confirmations"].as_u64().unwrap() >= 1);

    // The wallet sees the deposit to alice with her label, the change,
    // and the spent coinbase note, all under the one txid.
    wait_for(Duration::from_secs(30), async || {
        call(addr, t, "listreceived", json!([1]))
            .await
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["label"] == "alice")
    })
    .await;
    let received = call(addr, t, "listreceived", json!([1])).await;
    let to_alice = received
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["label"] == "alice")
        .unwrap();
    assert_eq!(to_alice["amount"], "500");
    assert_eq!(to_alice["address_index"], 1);
    assert_eq!(to_alice["txid"], txid);
    let view = call(addr, t, "gettransaction", json!([txid])).await;
    assert_eq!(
        view["received"].as_array().unwrap().len(),
        2,
        "alice's note and the change"
    );
    assert_eq!(view["spent"].as_array().unwrap().len(), 1);
    assert_eq!(view["net"], "-1000", "only the 1000 payment is debited");
    assert_eq!(view["spent"][0]["spent_by"], json!(txid));
    assert_eq!(
        call_err(addr, t, "gettransaction", json!(["00".repeat(32)])).await,
        NOT_FOUND
    );
    let listed = call(addr, t, "listoperations", json!(["confirmed"])).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);

    // An impossible send fails and frees its notes; a queued one can be
    // cancelled but a confirmed one cannot.
    let broke = call(
        addr,
        t,
        "sendmany",
        json!([[
            {"address": customer_address, "amount": "99999999999999"},
        ]]),
    )
    .await;
    let broke_id = broke["operation_id"].as_u64().unwrap();
    wait_for(Duration::from_secs(30), async || {
        call(addr, t, "getoperationstatus", json!([broke_id])).await["status"] == "failed"
    })
    .await;
    let failed = call(addr, t, "getoperationstatus", json!([broke_id])).await;
    assert!(
        failed["error"].as_str().unwrap().contains("insufficient"),
        "{failed}"
    );
    assert_eq!(call(addr, t, "getbalance", json!([])).await["locked"], "0");
    assert_eq!(
        call_err(addr, t, "canceloperation", json!([id])).await,
        REJECTED
    );
    assert_eq!(
        call_err(addr, t, "getoperationstatus", json!([999])).await,
        NOT_FOUND
    );
    assert_eq!(
        call_err(
            addr,
            t,
            "sendmany",
            json!([[{"address": "tnull1junk", "amount": "1"}]])
        )
        .await,
        runtime::jsonrpc::INVALID_PARAMS
    );

    // Rescan from genesis finds the same notes again.
    let before = call(addr, t, "getwalletinfo", json!([])).await["notes"].clone();
    let received_before = call(addr, t, "listreceived", json!([])).await;
    call(addr, t, "rescan", json!([0])).await;
    wait_for(Duration::from_secs(60), async || {
        let info = call(addr, t, "getwalletinfo", json!([])).await;
        // Mining continues during the rescan, so the wallet can already
        // contain additional coinbase notes when it catches up.
        info["synced"] == true && info["notes"].as_u64() >= before.as_u64()
    })
    .await;
    let received_after = call(addr, t, "listreceived", json!([])).await;
    for note in received_before.as_array().unwrap() {
        assert!(
            received_after.as_array().unwrap().iter().any(|rescanned| {
                rescanned["position"] == note["position"]
                    && rescanned["txid"] == note["txid"]
                    && rescanned["amount"] == note["amount"]
            }),
            "rescan lost note {note}"
        );
    }

    daemon.shutdown_and_wait().await;
    node.shutdown().await;
}
