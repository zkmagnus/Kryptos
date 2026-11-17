//! Body requests use multiple peer streams with a two-body window per stream.
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
use p2p::message::{Inventory, Message};
use p2p::peer::version_info;
use p2p::transport::{split, ConnectionReader, ConnectionWriter};
use protocol::block::{Block, BlockHash};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use runtime::config::Config;
use runtime::miner::Template;
use runtime::node::{Handle, Request, Response};
use storage::store::Store;
mod common;
use common::TorFixture;
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;

const DEADLINE: Duration = Duration::from_secs(20);

/// Build real consensus-valid bodies once, without waiting for a live miner.
fn blocks() -> &'static [Block; 5] {
    static BLOCKS: OnceLock<[Block; 5]> = OnceLock::new();
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
        for _ in 0..4 {
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
    async fn connect(
        network: &TorFixture,
        node: &Handle,
        height: u32,
        genesis: BlockHash,
        nonce: u64,
    ) -> Self {
        let stream = network.connect(&network.endpoint(node)).await.unwrap();
        let (writer, reader) = split(stream);
        let mut peer = Self { writer, reader };
        peer.send(Message::Version(version_info(
            nonce,
            height,
            genesis,
            runtime::now(),
        )))
        .await;
        assert!(matches!(peer.next().await, Message::Version(_)));
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
async fn independent_body_windows_survive_a_helper_missing_its_blocks() {
    let [genesis, first, second, third, fourth] = blocks();
    let network = TorFixture::new();
    let node = listener(&network).await;
    let mut source = Peer::connect(&network, &node, 4, genesis.hash(), 71).await;
    source
        .until(|message| matches!(message, Message::GetHeaders { .. }))
        .await;
    let mut helper = Peer::connect(&network, &node, 4, genesis.hash(), 72).await;
    helper.barrier(70).await;
    source
        .send(Message::Headers(vec![
            first.header().clone(),
            second.header().clone(),
            third.header().clone(),
            fourth.header().clone(),
        ]))
        .await;
    // Both streams must receive requests before either supplies a body.
    let (source_message, helper_message) = tokio::join!(
        source.until(|message| matches!(message, Message::GetData(_))),
        helper.until(|message| matches!(message, Message::GetData(_))),
    );
    let Message::GetData(source_requests) = source_message else {
        panic!("body request")
    };
    let Message::GetData(helper_requests) = helper_message else {
        panic!("body request")
    };
    assert_eq!(source_requests.len(), p2p::sync::MAX_IN_FLIGHT_PER_PEER);
    assert_eq!(helper_requests.len(), p2p::sync::MAX_IN_FLIGHT_PER_PEER);
    assert!(source_requests
        .iter()
        .all(|item| !helper_requests.contains(item)));
    assert_eq!(
        source_requests,
        vec![
            Inventory::Block(first.hash()),
            Inventory::Block(second.hash())
        ]
    );
    assert_eq!(
        helper_requests,
        vec![
            Inventory::Block(third.hash()),
            Inventory::Block(fourth.hash())
        ]
    );
    // A helper on another branch must release its reservations immediately,
    // allowing the authenticated header source to supply those bodies.
    helper
        .send(Message::NotFound(helper_requests.clone()))
        .await;
    helper.barrier(73).await;
    source.send(Message::Block(Box::new(first.clone()))).await;
    source.send(Message::Block(Box::new(second.clone()))).await;
    let mut reassigned = Vec::new();
    while reassigned.len() < helper_requests.len() {
        let Message::GetData(items) = source
            .until(|message| matches!(message, Message::GetData(_)))
            .await
        else {
            panic!("reassigned body request")
        };
        reassigned.extend(items);
    }
    assert_eq!(reassigned, helper_requests);
    source.send(Message::Block(Box::new(third.clone()))).await;
    source.send(Message::Block(Box::new(fourth.clone()))).await;
    source.barrier(74).await;
    assert_eq!(status(&node).await, (4, fourth.hash(), false));
    node.shutdown().await;
}
