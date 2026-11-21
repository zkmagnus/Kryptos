//! Persistent chain state: the coin commitment tree frontier, the
//! nullifier set and the block store, all in one `redb` database so a
//! block is applied or reverted atomically.
//!
//! - [`tree`]: the commitment tree frontier and its encoding.
//! - [`store`]: the database, its tables, and atomic apply and revert.
#![deny(clippy::arithmetic_side_effects)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod error;
pub mod nullifier;
pub mod store;
pub mod tree;

pub use error::Error;
pub use nullifier::{NullifierPath, NullifierTransition, NULLIFIER_TREE_DEPTH};

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
