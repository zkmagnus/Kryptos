//! Protocol types: the objects that appear in transactions and the rules
//! that govern them.
//!
//! - [`amount`]: bounded monetary values and signed sums.
//! - [`address`]: diversified payment addresses and their encodings.
//! - [`coin`]: coins, their commitments and their nullifiers.
//! - [`nullifier`]: the nullifier newtype.
//! - [`encryption`]: coin plaintext layout, encryption and trial decryption.
//! - [`bytes`]: reader and writer helpers for canonical encodings.
//! - [`consensus`]: action classes, state accounting and size limits.
//! - [`action`]: one spend plus one output, the unit of a transaction.
//! - [`transaction`]: the transaction, its encoding, txid and sighash.
//! - [`validate`]: stateless validation and signature checks.
//! - [`builder`]: assembles a balanced, padded, signed transaction.
//! - [`block`]: block header, block, and their hashes.
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

pub mod action;
pub mod address;
pub mod amount;
pub mod block;
pub mod body_tree;
pub mod builder;
pub mod bytes;
pub mod coin;
pub mod compact;
pub mod consensus;
pub mod encryption;
mod error;
pub mod fee;
pub mod header_tree;
pub mod history;
pub mod nullifier;
pub mod state;
pub mod transaction;
pub mod tree_order;
pub mod tx_tree;
pub mod validate;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Proving and verifying keys shared by every test, built once.
#[cfg(test)]
pub(crate) mod test_keys {
    use std::sync::OnceLock;

    use transaction_proof::{ProvingKey, VerifyingKey};

    static PROVING: OnceLock<ProvingKey> = OnceLock::new();
    static VERIFYING: OnceLock<VerifyingKey> = OnceLock::new();

    pub(crate) fn proving_key() -> &'static ProvingKey {
        PROVING.get_or_init(|| ProvingKey::build().unwrap())
    }

    pub(crate) fn verifying_key() -> &'static VerifyingKey {
        VERIFYING.get_or_init(|| proving_key().verifying_key())
    }
}
