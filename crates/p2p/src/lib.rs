//! Networking: the Tor-only wire protocol, peer state, address
//! book, headers-first sync and Dandelion++ relay.
//!
//! Every protocol state machine here is pure: it takes messages, time and
//! randomness as inputs and returns events, so it is tested without
//! sockets. Only [`transport`] touches the network.
//!
//! - [`message`]: the message set and its canonical encoding.
//! - [`codec`]: length-prefixed framing of messages on a byte stream.
//! - [`address`]: validated Tor v3 identities and address encoding.
//! - [`peer`]: handshake, keepalive and misbehavior scoring for one peer.
//! - [`addrbook`]: known addresses, bans and connection candidates.
//! - [`sync`]: locators and headers-first block download.
//! - [`dandelion`]: stem and fluff routing of transactions.
//! - [`transport`]: a Tor stream running the framed application protocol,
//!   split into reader and writer halves.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod addrbook;
pub mod address;
pub mod codec;
pub mod dandelion;
mod error;
pub mod message;
pub mod peer;
mod random;
pub mod sync;
pub mod transport;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
