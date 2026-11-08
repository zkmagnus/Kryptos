//! Helpers shared by the node integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use node::node::{Handle, Request, Response};
use wallet::wallet::Wallet;

/// A reward mined at height 1 is in the tree after block 1 and spendable
/// from block 2 onward.
pub fn first_spendable_height() -> u32 {
    1
}

/// Scans `node`'s chain from genesis to `to` into `wallet`.
pub async fn scan_chain(node: &Handle, wallet: &Wallet, to: u32) {
    for h in 0..=to {
        let Response::Block(Some(block)) = node.request(Request::Block(h)).await.unwrap() else {
            panic!("block {h}")
        };
        wallet.scan(&block).unwrap();
    }
}
