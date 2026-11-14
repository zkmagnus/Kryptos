use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// An amount could not be represented in a required signed balance or an operation overflowed.
    #[error("amount out of range")]
    RawCoinOutOfRange,
    /// An address string or byte string could not be parsed.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// A byte string does not have the expected layout.
    #[error("malformed encoding: {0}")]
    Malformed(&'static str),
    /// A coin ciphertext decrypted but its contents were inconsistent.
    #[error("coin decryption failed: {0}")]
    CoinDecryption(&'static str),
    /// A transaction violates a stateless consensus rule.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(&'static str),
    /// A block violates a stateless consensus rule.
    #[error("invalid block: {0}")]
    InvalidBlock(&'static str),
    /// The chain has reached the last representable height.
    #[error("block height exhausted")]
    HeightExhausted,
    /// Input value does not match output value.
    #[error("transaction does not balance")]
    Unbalanced,
    /// More spends or outputs than the largest action class allows.
    #[error("too many actions")]
    TooManyActions,
    /// A cryptographic error from the lower layer.
    #[error(transparent)]
    Crypto(#[from] crypto::Error),
    /// A proving or verifying error from the circuit layer.
    #[error(transparent)]
    Circuit(#[from] transaction_proof::Error),
}
