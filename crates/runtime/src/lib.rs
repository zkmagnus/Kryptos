//! The node: wires the chain, mempool, networking and miner together.
//!
//! - [`config`]: what a node needs to start.
//! - [`node`]: the event loop that owns all state.
//! - [`net`]: listener, dialer and per-connection tasks.
//! - [`miner`]: the block template and mining task.
//! - [`rpc`]: the local line-oriented control socket.
//! - [`jsonrpc`]: JSON-RPC 2.0 over HTTP, for exchanges, pools and tools.
//! - [`cli`]: the `rhombus` commands.
//! - [`walletd`]: the `rhombus-wallet-rpc` daemon for exchanges.
//! - [`paths`]: per-user storage locations on Linux, macOS and Windows.
//! - [`shutdown`]: stop requests from Ctrl-C, service managers and Windows.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod cli;
pub mod config;
mod discovery;
mod error;
pub mod http;
pub mod jsonrpc;
pub mod logging;
pub mod metrics;
pub mod miner;
pub mod net;
pub mod node;
pub mod paths;
mod peers_file;
pub mod rpc;
pub mod shutdown;
pub mod tor;
pub mod walletd;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
