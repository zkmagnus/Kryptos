use thiserror::Error;

/// Errors produced by the wallet.
#[derive(Debug, Error)]
pub enum Error {
    /// The wallet file could not be opened or its permissions restricted.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A protocol or building error.
    #[error(transparent)]
    Protocol(#[from] protocol::Error),
    /// A key or encoding error.
    #[error(transparent)]
    Crypto(#[from] crypto::Error),
    /// The wallet database failed.
    #[error(transparent)]
    Db(#[from] redb::Error),
    /// The JSON backup could not be serialized or parsed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The wallet file is for another network, is not a wallet, or would
    /// be overwritten.
    #[error("wallet file does not match this network or already exists")]
    WrongWallet,
    /// The requested operation does not exist.
    #[error("no operation {0}")]
    NoOperation(u64),
    /// The operating system's random source failed.
    #[error("system randomness unavailable")]
    Entropy,
    /// A block arrived out of order.
    #[error("expected block at height {expected}, got {got}")]
    OutOfOrder {
        /// The height the wallet expected next.
        expected: u32,
        /// The height received.
        got: u32,
    },
    /// The seed phrase is not a valid BIP 39 mnemonic.
    #[error("invalid seed phrase: {0}")]
    SeedPhrase(String),
    /// The wallet file contradicts itself.
    #[error("corrupt wallet: {0}")]
    Corrupt(&'static str),
    /// The witness tree rejected an operation.
    #[error("witness tree: {0}")]
    Tree(String),
    /// A write was attempted through a read-only tree handle.
    #[error("witness tree opened read-only")]
    ReadOnly,
    /// No witness exists for the position: it is not an owned note or
    /// lies past the tip.
    #[error("no witness for position {0}")]
    NoWitness(u64),
    /// The height is older than the oldest retained checkpoint.
    #[error("cannot roll back to height {0}: checkpoint pruned")]
    RollbackTooDeep(u32),
    /// The wallet does not hold enough unspent value.
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds {
        /// Unspent value available.
        have: u64,
        /// Value required by requested outputs.
        need: u64,
    },
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Self::Db(redb::Error::from(e))
            }
        }
    )*};
}

from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);
