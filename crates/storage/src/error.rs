use thiserror::Error;

/// Errors produced by the storage layer.
#[derive(Debug, Error)]
pub enum Error {
    /// The database could not be opened or created.
    #[error(transparent)]
    Database(#[from] redb::DatabaseError),
    /// A transaction could not be started.
    #[error(transparent)]
    Transaction(#[from] redb::TransactionError),
    /// A table could not be opened.
    #[error(transparent)]
    Table(#[from] redb::TableError),
    /// A read or write failed.
    #[error(transparent)]
    Storage(#[from] redb::StorageError),
    /// A commit failed.
    #[error(transparent)]
    Commit(#[from] redb::CommitError),
    /// Stored bytes did not decode.
    #[error(transparent)]
    Protocol(#[from] protocol::Error),
    /// Stored bytes did not decode into a field element.
    #[error(transparent)]
    Crypto(#[from] crypto::Error),
    /// The database contents contradict themselves.
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
    /// The block does not extend the current tip.
    #[error("block does not extend the tip")]
    NotOnTip,
    /// The tree cannot take more commitments.
    #[error("commitment tree is full")]
    TreeFull,
    /// A nullifier was already present in the parent's spent set.
    #[error("nullifier already spent")]
    NullifierAlreadySpent,
    /// A block attempted to insert more nullifiers than protocol limits allow.
    #[error("nullifier batch exceeds block limits")]
    NullifierBatchTooLarge,
    /// A snapshot manifest, state root, checkpoint, or payload is inconsistent.
    #[error("snapshot verification failed: {0}")]
    Snapshot(&'static str),
    /// Snapshot installation was not authorized for this database state.
    #[error("snapshot install mode does not permit replacing this store")]
    SnapshotInstallMode,
}
