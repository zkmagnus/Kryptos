//! Regression tests for synchronization over explicit memory stream fixtures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::OnceLock;
use std::time::Duration;

use chain::chain::{Chain, Import};
use chain::params::ChainParams;
use chain::validate::{header_lookback, recent_headers};
use crypto::keys::SpendingKey;
use p2p::message::{Inventory, Message, MAX_HEADERS, MAX_INVENTORY};
use p2p::peer::version_info;
use p2p::transport::{split, ConnectionReader, ConnectionWriter};
use protocol::block::{Block, BlockHash};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::Config;
use runtime::miner::Template;
use runtime::node::{Handle, Request, Response, Submission};
use storage::store::Store;
mod common;
use common::TorFixture;
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;

const DEADLINE: Duration = Duration::from_secs(20);

/// Build real consensus-valid bodies once, without waiting for a live miner.
fn blocks() -> &'static [Block; 3] {
    static BLOCKS: OnceLock<[Block; 3]> = OnceLock::new();
    BLOCKS.get_or_init(|| {
        let mut rng = ChaCha20Rng::seed_from_u64(112);
        let pk = ProvingKey::build().unwrap();
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let payout = keys.default_address().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let params = ChainParams::test();
        let chain = Chain::new(
            Store::open(directory.path().join("chain.redb")).unwrap(),
            params,
            pk.verifying_key(),
        )
        .unwrap();
        let genesis = chain
            .store()
            .block(&chain.tip().unwrap().hash)
            .unwrap()
            .unwrap();
        let mut result = vec![genesis];
        for _ in 0..2 {
            let parent = result.last().unwrap().header().clone();
            let template = Template {
                recent: recent_headers(chain.store(), parent.height, header_lookback(&params))
                    .unwrap(),
                tree: chain.store().tree().unwrap(),
                transactions: Vec::new(),
                params,
                now: parent.timestamp.saturating_add(params.block_interval),
                parent,
            };
            let (mut header, transactions) = template.assemble(&payout, &pk, &mut rng).unwrap();
            assert!(chain.pow().mine(&mut header, 256, &mut rng).unwrap());
            let block = Block::new(header, transactions);
            assert_eq!(
                chain.import(&block, runtime::now(), &mut rng).unwrap(),
                Import::Extended
            );
            result.push(block);
        }
        result.try_into().unwrap()
    })
}

struct Peer {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

impl Peer {
    async fn connect(network: &TorFixture, node: &Handle, height: u32, genesis: BlockHash) -> Self {
        let stream = network.connect(&network.endpoint(node)).await.unwrap();
        let (writer, reader) = split(stream);
        let mut peer = Self { writer, reader };
        peer.send(Message::Version(version_info(
            77,
            height,
            genesis,
            runtime::now(),
        )))
        .await;
        let mut version = false;
        let mut verack = false;
        while !version || !verack {
            match peer.next().await {
                Message::Version(_) => version = true,
                Message::Verack => verack = true,
                other => panic!("unexpected handshake message: {other:?}"),
            }
        }
        peer.send(Message::Verack).await;
        peer
    }

    async fn send(&mut self, message: Message) {
        tokio::time::timeout(DEADLINE, self.writer.send(&message))
            .await
            .expect("peer write timed out")
            .unwrap();
    }

    async fn next(&mut self) -> Message {
        tokio::time::timeout(DEADLINE, self.reader.recv())
            .await
            .expect("peer read timed out")
            .unwrap()
    }

    async fn until(&mut self, matches: impl Fn(&Message) -> bool) -> Message {
        tokio::time::timeout(DEADLINE, async {
            loop {
                let message = self.next().await;
                if matches(&message) {
                    return message;
                }
                if let Message::Ping(nonce) = message {
                    self.send(Message::Pong(nonce)).await;
                }
            }
        })
        .await
        .expect("expected peer message did not arrive")
    }

    /// A pong means the actor has processed all preceding messages on this connection.
    async fn barrier(&mut self, nonce: u64) {
        self.send(Message::Ping(nonce)).await;
        self.until(|message| matches!(message, Message::Pong(n) if *n == nonce))
            .await;
    }
}

async fn status(node: &Handle) -> (u32, BlockHash, bool) {
    match tokio::time::timeout(DEADLINE, node.request(Request::Status))
        .await
        .expect("node actor stopped responding")
        .unwrap()
    {
        Response::Status {
            height,
            hash,
            syncing,
            ..
        } => (height, hash, syncing),
        other => panic!("unexpected status response: {other:?}"),
    }
}

async fn listener(network: &TorFixture) -> Handle {
    network
        .spawn(Config {
            p2p: true,
            ..Config::test()
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_before_parent_is_requested_again_and_applied_before_sync_finishes() {
    let [genesis, parent, child] = blocks();
    let network = TorFixture::new();
    let node = listener(&network).await;
    let mut peer = Peer::connect(&network, &node, 2, genesis.hash()).await;
    peer.until(|message| matches!(message, Message::GetHeaders { .. }))
        .await;
    peer.send(Message::Headers(vec![
        parent.header().clone(),
        child.header().clone(),
    ]))
    .await;
    let Message::GetData(requests) = peer
        .until(|message| matches!(message, Message::GetData(_)))
        .await
    else {
        unreachable!()
    };
    assert_eq!(
        requests,
        vec![
            Inventory::Block(parent.hash()),
            Inventory::Block(child.hash())
        ]
    );

    peer.send(Message::Block(Box::new(child.clone()))).await;
    peer.barrier(1).await;
    assert_eq!(status(&node).await, (0, genesis.hash(), true));

    peer.send(Message::Block(Box::new(parent.clone()))).await;
    let Message::GetData(retry) = peer
        .until(|message| matches!(message, Message::GetData(_)))
        .await
    else {
        unreachable!()
    };
    assert_eq!(retry, vec![Inventory::Block(child.hash())]);
    assert_eq!(status(&node).await, (1, parent.hash(), true));

    peer.send(Message::Block(Box::new(child.clone()))).await;
    peer.barrier(2).await;
    assert_eq!(status(&node).await, (2, child.hash(), false));
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("peers response")
    };
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].score, 0,
        "reordered valid bodies are not misbehavior"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_known_headers_release_sync_and_mining_readiness() {
    let [genesis, parent, _] = blocks();
    let network = TorFixture::new();
    let node = listener(&network).await;
    assert!(matches!(
        node.request(Request::SubmitBlock(Box::new(parent.clone())))
            .await
            .unwrap(),
        Response::BlockSubmitted(Submission::Accepted)
    ));
    let mut peer = Peer::connect(&network, &node, 2, genesis.hash()).await;
    peer.until(|message| matches!(message, Message::GetHeaders { .. }))
        .await;
    assert!(status(&node).await.2);
    peer.send(Message::Headers(vec![parent.header().clone(); MAX_HEADERS]))
        .await;
    peer.barrier(3).await;

    assert_eq!(status(&node).await, (1, parent.hash(), false));
    assert!(matches!(
        node.request(Request::MiningReadiness).await.unwrap(),
        Response::MiningReadiness(None)
    ));
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("peers response")
    };
    assert_eq!(peers.len(), 1);
    assert!(peers[0].score > 0);
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_block_requests_are_served_once_and_leave_the_actor_responsive() {
    let genesis = chain::genesis::genesis(&ChainParams::test());
    let network = TorFixture::new();
    let node = listener(&network).await;
    let mut peer = Peer::connect(&network, &node, 0, genesis.hash()).await;
    peer.barrier(4).await;
    peer.send(Message::GetData(vec![
        Inventory::Block(genesis.hash());
        MAX_INVENTORY
    ]))
    .await;
    peer.send(Message::Ping(5)).await;

    let copies = tokio::time::timeout(DEADLINE, async {
        let mut copies = 0;
        loop {
            match peer.next().await {
                Message::Block(block) => {
                    assert_eq!(*block, genesis);
                    copies += 1;
                }
                Message::Pong(5) => return copies,
                Message::Ping(nonce) => peer.send(Message::Pong(nonce)).await,
                _ => {}
            }
        }
    })
    .await
    .expect("bulk serving prevented a ping response");
    assert_eq!(
        copies, 1,
        "duplicates must not allocate independent replies"
    );
    assert_eq!(status(&node).await, (0, genesis.hash(), false));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_unique_data_request_is_disconnected_before_serving() {
    let genesis = chain::genesis::genesis(&ChainParams::test());
    let network = TorFixture::new();
    let node = listener(&network).await;
    let mut peer = Peer::connect(&network, &node, 0, genesis.hash()).await;
    peer.barrier(6).await;
    // Exceed the wire inventory limit. Include one real stored
    // block to distinguish rejecting the entire request from partial service.
    let mut items = vec![Inventory::Block(genesis.hash())];
    items.extend((0..u32::try_from(MAX_INVENTORY).unwrap()).map(|index| {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        Inventory::Block(BlockHash::from_bytes(bytes))
    }));
    peer.send(Message::GetData(items)).await;
    tokio::time::timeout(DEADLINE, async {
        loop {
            match peer.reader.recv().await {
                Err(_) => break,
                Ok(Message::Block(_) | Message::NotFound(_)) => {
                    panic!("oversized request was partially served")
                }
                Ok(Message::Ping(nonce)) => peer.send(Message::Pong(nonce)).await,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("peer socket was retained after request rejection");
    assert_eq!(status(&node).await, (0, genesis.hash(), false));
    // EOF precedes delivery of the connection task's Disconnected event.
    // Requests from this test use another sender and can reach the actor first.
    tokio::time::timeout(DEADLINE, async {
        loop {
            let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
                panic!("peers response")
            };
            if peers.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnected peer remained in the actor's peer table");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_large_data_request_is_served_incrementally_without_disconnect() {
    let [genesis, parent, _] = blocks();
    let network = TorFixture::new();
    let node = listener(&network).await;
    assert!(matches!(
        node.request(Request::SubmitBlock(Box::new(parent.clone())))
            .await
            .unwrap(),
        Response::BlockSubmitted(Submission::Accepted)
    ));
    let mut peer = Peer::connect(&network, &node, 1, genesis.hash()).await;
    peer.barrier(7).await;
    let missing: Vec<Inventory> = (0..128u32)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&index.to_le_bytes());
            Inventory::Block(BlockHash::from_bytes(bytes))
        })
        .collect();
    let mut items = vec![Inventory::Block(parent.hash())];
    items.extend_from_slice(&missing);
    peer.send(Message::GetData(items)).await;

    tokio::time::timeout(DEADLINE, async {
        let mut received_block = false;
        let mut unavailable = Vec::new();
        while !received_block || unavailable.len() < missing.len() {
            match peer.next().await {
                Message::Block(block) => {
                    assert!(!received_block, "block served more than once");
                    assert_eq!(*block, *parent);
                    received_block = true;
                }
                Message::NotFound(items) => unavailable.extend(items),
                Message::Ping(nonce) => peer.send(Message::Pong(nonce)).await,
                _ => {}
            }
        }
        assert_eq!(unavailable, missing);
    })
    .await
    .expect("valid inventory did not finish incremental service");
    peer.barrier(8).await;
    assert_eq!(status(&node).await, (1, parent.hash(), false));
    let Response::Peers(peers) = node.request(Request::Peers).await.unwrap() else {
        panic!("peers response")
    };
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].score, 0);
    node.shutdown().await;
}
