//! Scanning, note management and transaction building.
//!
//! - [`seed`]: BIP 39 seed phrases, the human backup of a spending key.
//! - [`keys`]: a wallet's key material from a spending key.
//! - [`scan`]: trial decryption of one block's actions.
//! - [`tree`]: the sharded witness tree, pruned to what owned notes need.
//! - [`wallet`]: the persistent wallet: witness tree, owned notes, spent
//!   status, scanned heights, reorg rollback and witnesses.
//! - [`spend`]: selects notes and builds a payment.
//!
//! Wallet files store key material and notes in plaintext, alongside the
//! witness tree and scanned heights. Anyone who can read the file can
//! access its secrets and spend its funds.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod error;
pub mod keys;
pub mod operations;
pub mod scan;
pub mod seed;
pub mod spend;
pub mod tree;
pub mod wallet;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
