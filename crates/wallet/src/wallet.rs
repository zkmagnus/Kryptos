//! The persistent wallet. Wallet secrets are stored in plaintext.
//!
//! Tables:
//!
//! | table | key | value |
//! |---|---|---|
//! | `meta` | name | spending key, fingerprint, genesis |
//! | `coins` | tree position | owned coin |
//! | `heights` | height | block hash, tree size before the block |
//! | `shards`, `cap`, `checkpoints` | see [`crate::tree`] | the witness tree |
//!
//! The witness tree and scanned heights are stored alongside wallet data.
//! Scanning a block is one write transaction
//! that appends the block's commitments to the witness tree and takes a
//! checkpoint at its height; a reorganization is handled by rolling back
//! to the last matching height, which truncates the tree to that
//! checkpoint.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crypto::diversifier::DiversifierIndex;
use crypto::keys::SpendingKey;
use crypto::merkle::{MerklePath, Node};
use incrementalmerkletree::Position;
use protocol::address::RhombusAddress;
use protocol::block::{Block, BlockHash};
use protocol::bytes::Encodable;
use protocol::compact::CompactBlock;
use protocol::transaction::Anchor;
use protocol::tree_order::tree_transactions;
use rand_core::{CryptoRng, RngCore};
use redb::{
    Database, ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable, Table,
    TableDefinition, WriteTransaction,
};

use crate::keys::{ScanKeys, WalletKeys, MAX_SCAN_ADDRESSES};
use crate::operations::{Operation, OperationStatus};
#[cfg(test)]
use crate::scan::scan_block;
use crate::scan::{scan_block_with_keys, scan_compact_block_with_keys, BlockScan, OwnedCoin};
use crate::spend::Payment;
use crate::tree::{
    anchor_of, retention, to_merkle_path, witness_tree, WitnessTree, CAP, CHECKPOINTS, SHARDS,
};
use crate::{Error, Result};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const COINS: TableDefinition<u64, &[u8]> = TableDefinition::new("coins");
const COINS_BY_NULLIFIER: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("coins_by_nullifier");
const HEIGHTS: TableDefinition<u32, &[u8]> = TableDefinition::new("heights");
/// Diversifier index to the sealed label of an address handed out.
const ADDRESSES: TableDefinition<u64, &[u8]> = TableDefinition::new("addresses");
/// Operation id to the sealed operation.
const OPERATIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("operations");

const SPENDING_KEY: &str = "spending_key";
const FINGERPRINT: &str = "fingerprint";
const GENESIS: &str = "genesis";
/// The next diversifier index to allocate. Issued indices are never reused.
const NEXT_ADDRESS: &str = "next_address";
/// Active receiving index, or the sentinel when a fresh address is needed.
const CURRENT_RECEIVE_ADDRESS: &str = "current_receive_address";
const RECEIVE_PENDING: u64 = u64::MAX;
const NEXT_OPERATION: &str = "next_operation";
/// Version of the wallet's address derivation metadata (not consensus).
const ADDRESS_KEY_SCHEME: &str = "address_key_scheme";
/// Indices below this threshold retain the legacy shared ML-KEM key.
const ADDRESS_KEY_START: &str = "address_key_start";
const COIN_INDEX_VERSION: &str = "coin_nullifier_index_version";

/// Half-open range of separate ML-KEM keys the wallet scans. The legacy
/// receiver key covers every legacy address independently of this range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressScanRange {
    /// First index using a separate key.
    pub start: u64,
    /// Next unallocated index; the scan range excludes this index.
    pub end: u64,
}

impl AddressScanRange {
    fn validate(self) -> Result<Self> {
        if self.end == 0 || self.start > self.end {
            return Err(Error::Corrupt("invalid address scan range"));
        }
        if self.start != self.end && self.end > MAX_SCAN_ADDRESSES {
            return Err(crypto::Error::InvalidDerivation(
                "address scan range exceeds the local limit of 4096 keys",
            )
            .into());
        }
        Ok(self)
    }
}

const TAG_SPENDING_KEY: u8 = 0;
const TAG_COIN: u8 = 1;
const TAG_LABEL: u8 = 2;
const TAG_OPERATION: u8 = 3;

/// Open the exact file redb will use, restricting access before any wallet
/// secrets are written or read. Unix wallets are owner-only from creation;
/// other platforms retain their inherited filesystem ACLs.
fn open_wallet_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a replaced final path component to another file.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wallet path must be a regular file",
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // mode() only affects creation. Repair permissions on old wallets too,
        // using the handle so a path replacement cannot redirect this chmod.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct FileKey;

impl FileKey {
    fn seal(&self, _tag: u8, _position: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, _tag: u8, _position: u64, stored: &[u8]) -> Result<Vec<u8>> {
        Ok(stored.to_vec())
    }
}

/// A wallet database with its keys unlocked.
pub struct Wallet {
    db: Database,
    keys: WalletKeys,
    file_key: FileKey,
    scan_keys: Mutex<Option<(AddressScanRange, Arc<ScanKeys>)>>,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Wallet(<unlocked>)")
    }
}

/// What one scanned block changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Coins found for the wallet.
    pub found: usize,
    /// Wallet coins the block spent.
    pub spent: usize,
}

/// The witness tree over a read transaction.
type ReadTree = WitnessTree<
    ReadOnlyTable<u64, &'static [u8]>,
    ReadOnlyTable<(), &'static [u8]>,
    ReadOnlyTable<u32, &'static [u8]>,
>;

/// The witness tree over a write transaction.
type WriteTree<'txn> = WitnessTree<
    Table<'txn, u64, &'static [u8]>,
    Table<'txn, (), &'static [u8]>,
    Table<'txn, u32, &'static [u8]>,
>;

fn read_tree(tx: &ReadTransaction) -> Result<ReadTree> {
    Ok(witness_tree(
        tx.open_table(SHARDS)?,
        tx.open_table(CAP)?,
        tx.open_table(CHECKPOINTS)?,
    ))
}

fn write_tree(tx: &WriteTransaction) -> Result<WriteTree<'_>> {
    Ok(witness_tree(
        tx.open_table(SHARDS)?,
        tx.open_table(CAP)?,
        tx.open_table(CHECKPOINTS)?,
    ))
}

/// Number of leaves in a tree: the greatest position plus one.
fn size_of<S, P, C>(tree: &WitnessTree<S, P, C>) -> Result<u64>
where
    S: crate::tree::Slot<u64>,
    P: crate::tree::Slot<()>,
    C: crate::tree::Slot<u32>,
{
    Ok(tree
        .max_leaf_position(None)?
        .map_or(0, |p| u64::from(p).saturating_add(1)))
}

impl Wallet {
    /// Exports a complete, versioned JSON backup of wallet state. Secret keys
    /// and owned coins are included in plaintext, so the caller must protect
    /// the resulting file like the live wallet.
    ///
    /// # Errors
    /// Fails on a database or JSON value conversion error.
    pub fn backup_json(&self) -> Result<Vec<u8>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        let meta_rows = meta
            .iter()?
            .map(|row| {
                let (key, value) = row?;
                Ok(serde_json::json!({
                    "key": key.value(),
                    "value_hex": crypto::encoding::to_hex(value.value()),
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        macro_rules! rows {
            ($table:ident) => {{
                let table = tx.open_table($table)?;
                table
                    .iter()?
                    .map(|row| {
                        let (key, value) = row?;
                        Ok(serde_json::json!({
                            "key": key.value(),
                            "value_hex": crypto::encoding::to_hex(value.value()),
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?
            }};
        }
        let coins = rows!(COINS);
        let heights = rows!(HEIGHTS);
        let shards = rows!(SHARDS);
        let cap = rows!(CAP);
        let checkpoints = rows!(CHECKPOINTS);
        let addresses = rows!(ADDRESSES);
        let operations = rows!(OPERATIONS);
        let backup = serde_json::json!({
            "format": "rhombus-wallet-backup",
            "version": 2,
            "encoding": "hex",
            "plaintext_secrets": true,
            "tables": {
                "meta": meta_rows,
                "coins": coins,
                "heights": heights,
                "shards": shards,
                "cap": cap,
                "checkpoints": checkpoints,
                "addresses": addresses,
                "operations": operations,
            }
        });
        Ok(serde_json::to_vec_pretty(&backup)?)
    }

    /// Creates a plaintext wallet file for `sk`. Fails if the file is initialized.
    /// Unix files are created with owner-only access; symlinks are refused.
    ///
    /// # Errors
    /// Returns [`Error::WrongWallet`] if the file is already initialized,
    /// or a key derivation or database error.
    pub fn create(
        path: impl AsRef<Path>,
        sk: &SpendingKey,
        genesis: BlockHash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let keys = WalletKeys::from_spending_key(sk.clone())?;
        Self::create_with(
            path,
            keys,
            genesis,
            AddressScanRange { start: 0, end: 1 },
            Some(0),
            rng,
        )
    }

    /// Creates a fresh recovery wallet scanning every new address from zero
    /// through `last_address_index` inclusive, plus every legacy address.
    /// The caller must supply a bound covering all previously issued addresses.
    /// A larger bound later requires a fresh wallet and a historical rescan.
    ///
    /// # Errors
    /// Rejects overflow or more than [`MAX_SCAN_ADDRESSES`] new keys before
    /// opening a file, and propagates creation errors.
    pub fn restore(
        path: impl AsRef<Path>,
        sk: &SpendingKey,
        genesis: BlockHash,
        last_address_index: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let end = last_address_index
            .checked_add(1)
            .ok_or(crypto::Error::InvalidDerivation(
                "recovery address index overflow",
            ))?;
        let range = AddressScanRange { start: 0, end }.validate()?;
        let keys = WalletKeys::from_spending_key(sk.clone())?;
        Self::create_with(path, keys, genesis, range, None, rng)
    }

    fn create_with(
        path: impl AsRef<Path>,
        keys: WalletKeys,
        genesis: BlockHash,
        range: AddressScanRange,
        receive_index: Option<u64>,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let file = open_wallet_file(path.as_ref(), true)?;
        let db = Database::builder().create_file(file)?;
        Self::init(db, keys, genesis, FileKey, range, receive_index)
    }

    /// Opens an existing plaintext wallet file, restricting its permissions to
    /// owner-only on Unix before reading keys. Unix symlinks are refused.
    ///
    /// # Errors
    /// Returns [`Error::WrongWallet`] if the file is for another network
    /// or is not a wallet, or a database error.
    pub fn open(path: impl AsRef<Path>, genesis: BlockHash) -> Result<Self> {
        let file = open_wallet_file(path.as_ref(), false)?;
        let db = Database::builder().create_file(file)?;
        let (stored_sk, stored_genesis) = {
            let tx = db.begin_read()?;
            let meta = tx.open_table(META)?;
            let stored_sk = meta.get(SPENDING_KEY)?.map(|v| v.value().to_vec());
            let stored = meta
                .get(GENESIS)?
                .map(|v| v.value().to_vec())
                .ok_or(Error::WrongWallet)?;
            (stored_sk, stored)
        };
        if stored_genesis != genesis.as_bytes() {
            return Err(Error::WrongWallet);
        }
        let stored = stored_sk.ok_or(Error::WrongWallet)?;
        let sk_bytes: [u8; 32] = stored
            .try_into()
            .map_err(|_| Error::Corrupt("spending key"))?;
        let mut keys = WalletKeys::from_spending_key(SpendingKey::from_bytes(sk_bytes))?;
        let range = Self::migrate_address_scheme(&db)?;
        let file_key = FileKey;
        Self::migrate_coin_nullifier_index(&db, &file_key)?;
        if range.start > 0 {
            keys.set_legacy_default();
        }
        Ok(Self {
            db,
            keys,
            file_key,
            scan_keys: Mutex::new(None),
        })
    }

    fn init(
        db: Database,
        keys: WalletKeys,
        genesis: BlockHash,
        file_key: FileKey,
        range: AddressScanRange,
        receive_index: Option<u64>,
    ) -> Result<Self> {
        let sealed_key = file_key.seal(TAG_SPENDING_KEY, 0, &keys.spending_key().to_bytes())?;
        let tx = db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            tx.open_table(COINS)?;
            tx.open_table(COINS_BY_NULLIFIER)?;
            tx.open_table(HEIGHTS)?;
            tx.open_table(SHARDS)?;
            tx.open_table(CAP)?;
            tx.open_table(CHECKPOINTS)?;
            tx.open_table(ADDRESSES)?;
            tx.open_table(OPERATIONS)?;
            if meta.get(GENESIS)?.is_some() {
                return Err(Error::WrongWallet);
            }
            meta.insert(SPENDING_KEY, sealed_key.as_slice())?;
            meta.insert(FINGERPRINT, keys.fingerprint().as_slice())?;
            meta.insert(GENESIS, genesis.as_bytes().as_slice())?;
            meta.insert(ADDRESS_KEY_SCHEME, [1u8].as_slice())?;
            meta.insert(ADDRESS_KEY_START, range.start.to_le_bytes().as_slice())?;
            meta.insert(NEXT_ADDRESS, range.end.to_le_bytes().as_slice())?;
            meta.insert(
                CURRENT_RECEIVE_ADDRESS,
                receive_index
                    .unwrap_or(RECEIVE_PENDING)
                    .to_le_bytes()
                    .as_slice(),
            )?;
            meta.insert(COIN_INDEX_VERSION, [1u8].as_slice())?;
        }
        tx.commit()?;
        Ok(Self {
            db,
            keys,
            file_key,
            scan_keys: Mutex::new(None),
        })
    }

    fn migrate_address_scheme(db: &Database) -> Result<AddressScanRange> {
        let tx = db.begin_write()?;
        let range;
        {
            let mut meta = tx.open_table(META)?;
            let stored_next = meta
                .get(NEXT_ADDRESS)?
                .map(|v| decode_u64(v.value()))
                .transpose()?;
            let scheme = meta.get(ADDRESS_KEY_SCHEME)?.map(|v| v.value().to_vec());
            let start = meta
                .get(ADDRESS_KEY_START)?
                .map(|v| decode_u64(v.value()))
                .transpose()?;
            range = match (scheme.as_deref(), start) {
                (None, None) => {
                    let next = stored_next.unwrap_or(1);
                    // Every address already handed out keeps its exact bytes.
                    meta.insert(ADDRESS_KEY_SCHEME, [1u8].as_slice())?;
                    meta.insert(ADDRESS_KEY_START, next.to_le_bytes().as_slice())?;
                    meta.insert(NEXT_ADDRESS, next.to_le_bytes().as_slice())?;
                    AddressScanRange {
                        start: next,
                        end: next,
                    }
                }
                (Some([1]), Some(start)) => AddressScanRange {
                    start,
                    end: stored_next.ok_or(Error::Corrupt("missing address allocation counter"))?,
                },
                _ => return Err(Error::Corrupt("unsupported address key scheme")),
            }
            .validate()?;
            if scheme.is_none() || meta.get(CURRENT_RECEIVE_ADDRESS)?.is_none() {
                // Old and recovered addresses may already have been shared.
                // Preserve their identities but choose a fresh receiving index.
                meta.insert(
                    CURRENT_RECEIVE_ADDRESS,
                    RECEIVE_PENDING.to_le_bytes().as_slice(),
                )?;
            }
            read_receive_index(&meta, range)?;
            if tx
                .open_table(ADDRESSES)?
                .last()?
                .is_some_and(|(index, _)| index.value() >= range.end)
            {
                return Err(Error::Corrupt("issued address exceeds allocation counter"));
            }
        }
        tx.commit()?;
        Ok(range)
    }

    fn migrate_coin_nullifier_index(db: &Database, file_key: &FileKey) -> Result<()> {
        let tx = db.begin_write()?;
        let version = {
            let meta = tx.open_table(META)?;
            let value = meta.get(COIN_INDEX_VERSION)?;
            value.map(|value| value.value().to_vec())
        };
        match version.as_deref() {
            Some([1]) => {
                tx.commit()?;
                return Ok(());
            }
            Some(_) => return Err(Error::Corrupt("coin nullifier index version")),
            None => {}
        }

        {
            let coins = tx.open_table(COINS)?;
            let mut index = tx.open_table(COINS_BY_NULLIFIER)?;
            index.retain(|_, _| false)?;
            for row in coins.iter()? {
                let (position, value) = row?;
                let position = position.value();
                let plaintext = file_key.open(TAG_COIN, position, value.value())?;
                let coin = OwnedCoin::from_slice(&plaintext)?;
                if index
                    .insert(&coin.nullifier.to_bytes(), position)?
                    .is_some()
                {
                    return Err(Error::Corrupt("duplicate wallet nullifier"));
                }
            }
        }
        tx.open_table(META)?
            .insert(COIN_INDEX_VERSION, [1u8].as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// The separate-key address range currently covered by scans. Legacy
    /// payments at every diversifier are also checked.
    pub fn address_scan_range(&self) -> Result<AddressScanRange> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        read_address_range(&meta)
    }

    #[cfg(test)]
    fn scanning_keys(&self) -> Result<Arc<ScanKeys>> {
        self.scanning_keys_for(self.address_scan_range()?)
    }

    fn scanning_keys_for(&self, range: AddressScanRange) -> Result<Arc<ScanKeys>> {
        let mut cached = self
            .scan_keys
            .lock()
            .map_err(|_| Error::Corrupt("scan key cache poisoned"))?;
        if let Some((previous, keys)) = cached.as_ref() {
            if *previous == range {
                return Ok(Arc::clone(keys));
            }
        }
        let keys = Arc::new(ScanKeys::new(&self.keys, range.start, range.end)?);
        *cached = Some((range, Arc::clone(&keys)));
        Ok(keys)
    }

    /// The unlocked keys.
    pub fn keys(&self) -> &WalletKeys {
        &self.keys
    }

    /// Height of the next block to scan.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn next_height(&self) -> Result<u32> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        let next = heights
            .last()?
            .map_or(0, |(k, _)| k.value().saturating_add(1));
        Ok(next)
    }

    /// Number of leaves in the witness tree.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn tree_size(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        size_of(&read_tree(&tx)?)
    }

    /// The hash of the block scanned at `height`, if any.
    ///
    /// # Errors
    /// Fails on a database error or corrupt row.
    pub fn scanned_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        let hash = heights
            .get(height)?
            .map(|row| decode_height(row.value()).map(|(hash, _)| hash))
            .transpose();
        hash
    }

    /// Oldest height to which the witness tree can roll back.
    ///
    /// # Errors
    /// Fails on a database error or corrupt checkpoint.
    pub fn oldest_checkpoint(&self) -> Result<Option<u32>> {
        let tx = self.db.begin_read()?;
        let tree = read_tree(&tx)?;
        tree.store().oldest_checkpoint_id()
    }

    /// Scans the next full block: appends its commitments to the witness
    /// tree, marking the ones it owns, takes a checkpoint at the block's
    /// height, records owned coins marks coins it
    /// spent. All or nothing.
    ///
    /// Commitments enter in the block's transaction order.
    ///
    /// # Errors
    /// Returns [`Error::OutOfOrder`] if `block` is not the next height, or a
    /// protocol error if the block is malformed.
    pub fn scan(&self, block: &Block) -> Result<ScanReport> {
        let height = block.header().height;
        let tree = tree_transactions(block)?;
        self.apply(height, block.hash(), |keys, first_position| {
            scan_block_with_keys(&self.keys, keys, block, &tree, first_position)
        })
    }

    /// Scans the next block from its compact form, as a light client does.
    /// It maintains the same witness tree and finds the same coins.
    ///
    /// # Errors
    /// Returns [`Error::OutOfOrder`] if `block` is not the next height.
    pub fn scan_compact(&self, block: &CompactBlock) -> Result<ScanReport> {
        self.apply(block.height, block.hash, |keys, first_position| {
            scan_compact_block_with_keys(&self.keys, keys, block, first_position)
        })
    }

    /// Applies one scanned block in a single write transaction: appends
    /// leaves, checkpoints, records found coins and marks spends. Shared
    /// by the full and compact scanners.
    fn apply(
        &self,
        height: u32,
        hash: BlockHash,
        build: impl FnOnce(&ScanKeys, u64) -> Result<BlockScan>,
    ) -> Result<ScanReport> {
        let tx = self.db.begin_write()?;
        let expected = tx
            .open_table(HEIGHTS)?
            .last()?
            .map_or(0, |(height, _)| height.value().saturating_add(1));
        if height != expected {
            return Err(Error::OutOfOrder {
                expected,
                got: height,
            });
        }
        // Read the allocation range only after acquiring the writer. A concurrent
        // address allocation cannot commit between selecting keys and this scan.
        let range = read_address_range(&tx.open_table(META)?)?;
        let keys = self.scanning_keys_for(range)?;
        let mut report = ScanReport::default();
        {
            let mut tree = write_tree(&tx)?;
            let first_position = size_of(&tree)?;
            let scan = build(&keys, first_position)?;
            self.retire_received_address(&tx, &scan.found)?;
            report.found = scan.found.len();
            let owned: Vec<u64> = scan.found.iter().map(|n| n.position).collect();
            let leaves = scan.leaves.iter().enumerate().map(|(i, leaf)| {
                let position = first_position.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
                (Node::new(*leaf), retention(owned.contains(&position)))
            });
            tree.batch_insert(Position::from(first_position), leaves)?;
            if !tree.checkpoint(height)? {
                return Err(Error::Corrupt("checkpoint out of order"));
            }
            let mut coins = tx.open_table(COINS)?;
            let mut coin_index = tx.open_table(COINS_BY_NULLIFIER)?;
            for coin in &scan.found {
                coins.insert(coin.position, self.seal_coin(coin)?.as_slice())?;
                if coin_index
                    .insert(&coin.nullifier.to_bytes(), coin.position)?
                    .is_some()
                {
                    return Err(Error::Corrupt("duplicate wallet nullifier"));
                }
            }
            for (nullifier, spent_by) in &scan.spent {
                let Some(position) = coin_index
                    .get(&nullifier.to_bytes())?
                    .map(|value| value.value())
                else {
                    continue;
                };
                let plaintext = {
                    let value = coins
                        .get(position)?
                        .ok_or(Error::Corrupt("nullifier index points to missing coin"))?;
                    self.file_key.open(TAG_COIN, position, value.value())?
                };
                let mut coin = OwnedCoin::from_slice(&plaintext)?;
                if coin.nullifier != *nullifier {
                    return Err(Error::Corrupt("nullifier index mismatch"));
                }
                if coin.spent_at.is_none() {
                    coin.spent_at = Some(height);
                    coin.spent_by = *spent_by;
                    coins.insert(coin.position, self.seal_coin(&coin)?.as_slice())?;
                    // The mark is removed as of this checkpoint, so a
                    // rollback below it restores the witness.
                    tree.remove_mark(Position::from(coin.position), Some(&height))?;
                    report.spent = report.spent.saturating_add(1);
                }
            }
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.insert(height, encode_height(hash, first_position).as_slice())?;
        }
        tx.commit()?;
        Ok(report)
    }

    /// Forgets every block above `height`: tree leaves, coins created
    /// after it, and spends recorded after it. Reopens removed confirmations
    /// and reserves their inputs in the same database transaction.
    ///
    /// # Errors
    /// Returns [`Error::RollbackTooDeep`] if the checkpoint at `height`
    /// was pruned, or a database error.
    pub fn rollback_to(&self, height: u32) -> Result<()> {
        if self.next_height()? <= height.saturating_add(1) {
            return Ok(());
        }
        let tx = self.db.begin_write()?;
        {
            let mut tree = write_tree(&tx)?;
            if !tree.truncate_to_checkpoint(&height)? {
                return Err(Error::RollbackTooDeep(height));
            }
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.retain(|h, _| h <= height)?;
            let mut coins = tx.open_table(COINS)?;
            let mut coin_index = tx.open_table(COINS_BY_NULLIFIER)?;
            let owned = self.decrypt_all(&coins)?;
            for mut coin in owned {
                if coin.height > height {
                    coins.remove(coin.position)?;
                    coin_index.remove(&coin.nullifier.to_bytes())?;
                } else if coin.spent_at.is_some_and(|h| h > height) {
                    coin.spent_at = None;
                    coin.spent_by = None;
                    coins.insert(coin.position, self.seal_coin(&coin)?.as_slice())?;
                }
            }
            let mut operations = tx.open_table(OPERATIONS)?;
            for mut op in self.decrypt_operations(&operations)? {
                if let OperationStatus::Confirmed { txid, height: at } = op.status {
                    if at > height {
                        // The build height was no later than the confirmation.
                        // Using this upper bound delays expiry conservatively.
                        op.status = OperationStatus::Submitted { txid, built_at: at };
                        operations.insert(op.id, self.seal_operation(&op)?.as_slice())?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn seal_coin(&self, coin: &OwnedCoin) -> Result<Vec<u8>> {
        self.file_key.seal(TAG_COIN, coin.position, &coin.to_vec())
    }

    fn decrypt_all(
        &self,
        coins: &impl ReadableTable<u64, &'static [u8]>,
    ) -> Result<Vec<OwnedCoin>> {
        coins
            .iter()?
            .map(|row| {
                let (position, value) = row?;
                let plain = self
                    .file_key
                    .open(TAG_COIN, position.value(), value.value())?;
                Ok(OwnedCoin::from_slice(&plain)?)
            })
            .collect()
    }

    /// Every owned coin, spent or not, by position.
    ///
    /// # Errors
    /// Fails on a database error or corrupt row.
    pub fn coins(&self) -> Result<Vec<OwnedCoin>> {
        let tx = self.db.begin_read()?;
        let coins = tx.open_table(COINS)?;
        self.decrypt_all(&coins)
    }

    /// Coins not yet seen spent on chain.
    ///
    /// # Errors
    /// See [`Self::coins`].
    pub fn unspent(&self) -> Result<Vec<OwnedCoin>> {
        Ok(self
            .coins()?
            .into_iter()
            .filter(|n| n.spent_at.is_none())
            .collect())
    }

    /// Unspent value.
    ///
    /// # Errors
    /// See [`Self::coins`].
    pub fn balance(&self) -> Result<u64> {
        Ok(self.unspent()?.iter().map(|n| n.coin.value().raw()).sum())
    }

    /// The height of the last scanned block, which is the checkpoint
    /// witnesses are taken at.
    fn tip_height(&self) -> Result<u32> {
        self.next_height()?
            .checked_sub(1)
            .ok_or(Error::Corrupt("no block scanned"))
    }

    /// The tree root after the last scanned block.
    ///
    /// # Errors
    /// Fails before any block is scanned or on a database error.
    pub fn anchor(&self) -> Result<Anchor> {
        let tip = self.tip_height()?;
        let tx = self.db.begin_read()?;
        let root = read_tree(&tx)?
            .root_at_checkpoint_id(&tip)?
            .ok_or(Error::Corrupt("missing tip checkpoint"))?;
        Ok(anchor_of(&root))
    }

    /// Witnesses for owned coin positions, all against the anchor after
    /// the last scanned block, in the order given.
    ///
    /// # Errors
    /// Returns [`Error::NoWitness`] for a position that is not an unspent
    /// owned coin.
    pub fn witnesses(&self, positions: &[u64]) -> Result<(Vec<MerklePath>, Anchor)> {
        let tip = self.tip_height()?;
        let tx = self.db.begin_read()?;
        let tree = read_tree(&tx)?;
        let root = tree
            .root_at_checkpoint_id(&tip)?
            .ok_or(Error::Corrupt("missing tip checkpoint"))?;
        let paths = positions
            .iter()
            .map(|&position| {
                let path = tree
                    .witness_at_checkpoint_id(Position::from(position), &tip)
                    .ok()
                    .flatten()
                    .ok_or(Error::NoWitness(position))?;
                to_merkle_path(&path)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((paths, anchor_of(&root)))
    }

    /// The witness for one coin position and the anchor it is valid for.
    ///
    /// # Errors
    /// See [`Self::witnesses`].
    pub fn witness(&self, position: u64) -> Result<(MerklePath, Anchor)> {
        let (mut paths, anchor) = self.witnesses(&[position])?;
        let path = paths.pop().ok_or(Error::NoWitness(position))?;
        Ok((path, anchor))
    }

    /// The height of the last scanned block, or `None` before any.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn scanned_height(&self) -> Result<Option<u32>> {
        Ok(self.next_height()?.checked_sub(1))
    }

    /// Returns the persisted active receiving address, allocating a fresh one
    /// when a send or receipt retired the previous address. Returns `None` if
    /// the local address limit is exhausted; historical funds remain scannable.
    ///
    /// # Errors
    /// Fails on invalid metadata, key derivation or database errors.
    pub fn current_receive_address(&self) -> Result<Option<(u64, RhombusAddress)>> {
        {
            let tx = self.db.begin_read()?;
            let meta = tx.open_table(META)?;
            let range = read_address_range(&meta)?;
            if let Some(index) = read_receive_index(&meta, range)? {
                return Ok(Some((index, self.keys.address(index.into())?)));
            }
            if range.end >= MAX_SCAN_ADDRESSES {
                return Ok(None);
            }
        }
        let tx = self.db.begin_write()?;
        let current = {
            let meta = tx.open_table(META)?;
            read_receive_index(&meta, read_address_range(&meta)?)?
        };
        let result = if let Some(index) = current {
            Some((index, self.keys.address(index.into())?))
        } else if read_address_range(&tx.open_table(META)?)?.end >= MAX_SCAN_ADDRESSES {
            None
        } else {
            let (index, address) = self.allocate_address(&tx, "receive")?;
            tx.open_table(META)?
                .insert(CURRENT_RECEIVE_ADDRESS, index.to_le_bytes().as_slice())?;
            Some((index, address))
        };
        tx.commit()?;
        Ok(result)
    }

    /// Hands out a fresh diversified address under `label` and selects it as
    /// the active receiving address. Previous addresses remain valid.
    ///
    /// # Errors
    /// Fails on a database error or an exhausted index space.
    pub fn new_address(&self, label: &str) -> Result<(u64, RhombusAddress)> {
        let tx = self.db.begin_write()?;
        let result = self.allocate_address(&tx, label)?;
        tx.open_table(META)?
            .insert(CURRENT_RECEIVE_ADDRESS, result.0.to_le_bytes().as_slice())?;
        tx.commit()?;
        Ok(result)
    }

    fn allocate_address(
        &self,
        tx: &WriteTransaction,
        label: &str,
    ) -> Result<(u64, RhombusAddress)> {
        let mut meta = tx.open_table(META)?;
        let range = read_address_range(&meta)?;
        let index = range.end;
        if index >= MAX_SCAN_ADDRESSES {
            return Err(crypto::Error::InvalidDerivation(
                "new address index exceeds 4095; use another account or wallet",
            )
            .into());
        }
        let next = index
            .checked_add(1)
            .ok_or(Error::Corrupt("address index exhausted"))?;
        AddressScanRange {
            start: range.start,
            end: next,
        }
        .validate()?;
        let address = self.keys.address(index.into())?;
        let sealed = self.file_key.seal(TAG_LABEL, index, label.as_bytes())?;
        tx.open_table(ADDRESSES)?.insert(index, sealed.as_slice())?;
        meta.insert(NEXT_ADDRESS, next.to_le_bytes().as_slice())?;
        Ok((index, address))
    }

    /// Reserves a distinct change address when needed and retires the active
    /// receive address before proving a new transaction. Allocation survives
    /// proof failure or cancellation; rebroadcasts reuse their recorded bytes.
    ///
    /// # Errors
    /// Fails if change needs an unavailable address or on a database error.
    pub(crate) fn reserve_send_address(
        &self,
        needs_change: bool,
    ) -> Result<Option<RhombusAddress>> {
        let tx = self.db.begin_write()?;
        let change = if needs_change {
            Some(self.allocate_address(&tx, "change")?.1)
        } else {
            None
        };
        tx.open_table(META)?.insert(
            CURRENT_RECEIVE_ADDRESS,
            RECEIVE_PENDING.to_le_bytes().as_slice(),
        )?;
        tx.commit()?;
        Ok(change)
    }

    fn retire_received_address(&self, tx: &WriteTransaction, found: &[OwnedCoin]) -> Result<()> {
        let mut meta = tx.open_table(META)?;
        let Some(index) = read_receive_index(&meta, read_address_range(&meta)?)? else {
            return Ok(());
        };
        if found.is_empty() {
            return Ok(());
        }
        let current = self.keys.address(index.into())?;
        if found
            .iter()
            .any(|coin| !coin.legacy_address && coin.coin.diversifier() == current.diversifier())
        {
            meta.insert(
                CURRENT_RECEIVE_ADDRESS,
                RECEIVE_PENDING.to_le_bytes().as_slice(),
            )?;
        }
        Ok(())
    }

    /// Every address handed out, with its index and label, plus the
    /// default address at index zero.
    ///
    /// # Errors
    /// Fails on a database error or a label that does not decrypt.
    pub fn addresses(&self) -> Result<Vec<(u64, RhombusAddress, String)>> {
        let range = self.address_scan_range()?;
        let tx = self.db.begin_read()?;
        let addresses = tx.open_table(ADDRESSES)?;
        let mut out = vec![(0, self.keys.default_address()?, String::new())];
        for row in addresses.iter()? {
            let (index, sealed) = row?;
            let index = index.value();
            let label = self.file_key.open(TAG_LABEL, index, sealed.value())?;
            out.push((
                index,
                if index < range.start {
                    self.keys.legacy_address(DiversifierIndex::from(index))?
                } else {
                    self.keys.address(DiversifierIndex::from(index))?
                },
                String::from_utf8(label).map_err(|_| Error::Corrupt("label"))?,
            ));
        }
        Ok(out)
    }

    /// The index of one of our addresses, if it is ours and fits the
    /// wallet's `u64` index space.
    pub fn address_index_of(&self, address: &RhombusAddress) -> Option<u64> {
        let index = self.keys.index_of(address)?;
        let bytes = index.as_bytes();
        let (low, high) = bytes.split_at(8);
        high.iter()
            .all(|b| *b == 0)
            .then(|| u64::from_le_bytes(low.try_into().unwrap_or([0; 8])))
    }

    /// Whether the configured scan keys currently cover this address.
    /// Ownership alone does not imply that an arbitrary new index is scanned.
    pub fn scans_address(&self, address: &RhombusAddress) -> Result<bool> {
        let Some(index) = self.address_index_of(address) else {
            return Ok(false);
        };
        if self.keys.legacy_address(index.into())? == *address {
            return Ok(true);
        }
        let range = self.address_scan_range()?;
        Ok((range.start..range.end).contains(&index))
    }

    /// Records a new queued operation and returns it with its id.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn add_operation(
        &self,
        payment: Option<Payment>,
        min_confirmations: u32,
        created_at: u64,
    ) -> Result<Operation> {
        let tx = self.db.begin_write()?;
        let operation;
        {
            let mut meta = tx.open_table(META)?;
            let id = meta
                .get(NEXT_OPERATION)?
                .map(|v| decode_u64(v.value()))
                .transpose()?
                .unwrap_or(1);
            operation = Operation::new(id, created_at, payment, min_confirmations);
            tx.open_table(OPERATIONS)?
                .insert(id, self.seal_operation(&operation)?.as_slice())?;
            meta.insert(
                NEXT_OPERATION,
                id.checked_add(1)
                    .ok_or(Error::Corrupt("operation id exhausted"))?
                    .to_le_bytes()
                    .as_slice(),
            )?;
        }
        tx.commit()?;
        Ok(operation)
    }

    /// Stores the current state of an operation.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn put_operation(&self, operation: &Operation) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut operations = tx.open_table(OPERATIONS)?;
            operations.insert(operation.id, self.seal_operation(operation)?.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces an operation only if its persisted state still equals `previous`.
    /// Returns false if another writer changed it, so a cancellation or rollback
    /// cannot be overwritten by a worker holding an older snapshot.
    ///
    /// # Errors
    /// Fails on a database/decoding error or if the ids differ.
    pub fn compare_and_swap_operation(
        &self,
        previous: &Operation,
        operation: &Operation,
    ) -> Result<bool> {
        if previous.id != operation.id {
            return Err(Error::Corrupt("operation ids differ"));
        }
        let tx = self.db.begin_write()?;
        {
            let mut operations = tx.open_table(OPERATIONS)?;
            let Some(sealed) = operations.get(previous.id)? else {
                return Ok(false);
            };
            let current = self.open_operation(previous.id, sealed.value())?;
            if current != *previous {
                return Ok(false);
            }
            drop(sealed);
            operations.insert(operation.id, self.seal_operation(operation)?.as_slice())?;
        }
        tx.commit()?;
        Ok(true)
    }

    fn open_operation(&self, id: u64, sealed: &[u8]) -> Result<Operation> {
        let plain = self.file_key.open(TAG_OPERATION, id, sealed)?;
        Ok(Operation::from_slice(&plain)?)
    }

    fn decrypt_operations(
        &self,
        operations: &impl ReadableTable<u64, &'static [u8]>,
    ) -> Result<Vec<Operation>> {
        operations
            .iter()?
            .map(|row| {
                let (id, sealed) = row?;
                self.open_operation(id.value(), sealed.value())
            })
            .collect()
    }

    /// Every operation, oldest first.
    ///
    /// # Errors
    /// Fails on a database error or a record that does not decrypt.
    pub fn operations(&self) -> Result<Vec<Operation>> {
        let tx = self.db.begin_read()?;
        let operations = tx.open_table(OPERATIONS)?;
        self.decrypt_operations(&operations)
    }

    /// One operation by id.
    ///
    /// # Errors
    /// Returns [`Error::NoOperation`] if there is none.
    pub fn operation(&self, id: u64) -> Result<Operation> {
        self.operations()?
            .into_iter()
            .find(|op| op.id == id)
            .ok_or(Error::NoOperation(id))
    }

    /// Positions of coins set aside by pending operations, which a new
    /// send must not touch.
    ///
    /// # Errors
    /// See [`Self::operations`].
    pub fn locked_positions(&self) -> Result<Vec<u64>> {
        Ok(self
            .operations()?
            .iter()
            .filter(|op| op.status.is_pending())
            .flat_map(|op| op.locked.iter().copied())
            .collect())
    }

    fn seal_operation(&self, operation: &Operation) -> Result<Vec<u8>> {
        self.file_key
            .seal(TAG_OPERATION, operation.id, &operation.to_vec())
    }
}

fn read_address_range(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<AddressScanRange> {
    let read = |name| -> Result<u64> {
        decode_u64(
            meta.get(name)?
                .ok_or(Error::Corrupt("missing address range"))?
                .value(),
        )
    };
    AddressScanRange {
        start: read(ADDRESS_KEY_START)?,
        end: read(NEXT_ADDRESS)?,
    }
    .validate()
}

fn read_receive_index(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    range: AddressScanRange,
) -> Result<Option<u64>> {
    let index = decode_u64(
        meta.get(CURRENT_RECEIVE_ADDRESS)?
            .ok_or(Error::Corrupt("missing receive address"))?
            .value(),
    )?;
    if index == RECEIVE_PENDING {
        return Ok(None);
    }
    if !(range.start..range.end).contains(&index) {
        return Err(Error::Corrupt(
            "receive address exceeds allocated key range",
        ));
    }
    Ok(Some(index))
}

/// A little-endian `u64` meta value.
fn decode_u64(bytes: &[u8]) -> Result<u64> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| Error::Corrupt("u64 meta value"))
}

/// A height row: `hash || first position`.
fn encode_height(hash: BlockHash, first_position: u64) -> Vec<u8> {
    let mut out = hash.as_bytes().to_vec();
    out.extend_from_slice(&first_position.to_le_bytes());
    out
}

fn decode_height(bytes: &[u8]) -> Result<(BlockHash, u64)> {
    let hash: [u8; 32] = bytes
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Corrupt("height row"))?;
    let first: [u8; 8] = bytes
        .get(32..40)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Corrupt("height row"))?;
    Ok((BlockHash::from_bytes(hash), u64::from_le_bytes(first)))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use crypto::pallas;
    use protocol::amount::RawCoin;
    use protocol::block::{empty_header, BlockHeader};
    use protocol::builder::{Builder, OutputInfo, SpendInfo};
    use protocol::consensus::BranchId;
    use protocol::transaction::Transaction;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use transaction_proof::ProvingKey;

    use super::*;

    static PK: OnceLock<ProvingKey> = OnceLock::new();

    /// The branch every test transaction is signed for.
    const BRANCH: BranchId = BranchId::new(1);

    fn pk() -> &'static ProvingKey {
        PK.get_or_init(|| ProvingKey::build().unwrap())
    }

    fn sk(seed: u64) -> SpendingKey {
        SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    fn temp_wallet(
        spending_key: &SpendingKey,
        genesis: BlockHash,
        rng: &mut ChaCha20Rng,
    ) -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::tempdir().unwrap();
        let wallet =
            Wallet::create(dir.path().join("wallet.redb"), spending_key, genesis, rng).unwrap();
        (dir, wallet)
    }

    /// The stored coin record at `position`.
    fn raw_coin(wallet: &Wallet, position: u64) -> Vec<u8> {
        let tx = wallet.db.begin_read().unwrap();
        let coins = tx.open_table(COINS).unwrap();
        coins.get(position).unwrap().unwrap().value().to_vec()
    }

    fn indexed_position(
        wallet: &Wallet,
        nullifier: &protocol::nullifier::Nullifier,
    ) -> Option<u64> {
        let tx = wallet.db.begin_read().unwrap();
        let index = tx.open_table(COINS_BY_NULLIFIER).unwrap();
        index
            .get(&nullifier.to_bytes())
            .unwrap()
            .map(|value| value.value())
    }

    /// A block at `height` paying `value` to `keys` through a coinbase.
    fn coinbase_block(
        rng: &mut ChaCha20Rng,
        keys: &WalletKeys,
        prev: BlockHash,
        height: u32,
        value: u64,
    ) -> Block {
        let mut b = Builder::new(Anchor::from_base(pallas::Base::from(0u64)));
        let credit = RawCoin::from_raw(value).unwrap();
        b.add_output(OutputInfo::new(
            keys.default_address().unwrap(),
            credit,
            None,
        ))
        .unwrap();
        let tx = b.build_coinbase(pk(), credit, BRANCH, rng).unwrap();
        let mut header: BlockHeader = empty_header(
            height,
            prev,
            Anchor::from_base(pallas::Base::from(u64::from(height))),
        );
        header.tx_root = protocol::block::tx_root([tx.txid()]);
        Block::new(header, vec![tx])
    }

    #[test]
    fn wallet_files_match_their_network_and_do_not_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");
        let genesis = BlockHash::from_bytes([1; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let created = Wallet::create(&path, &sk(1), genesis, &mut rng).unwrap();
        let address = created.keys().default_address().unwrap();
        drop(created);
        assert!(Wallet::open(&path, genesis).is_ok());
        assert!(matches!(
            Wallet::open(&path, BlockHash::ZERO),
            Err(Error::WrongWallet)
        ));
        let opened = Wallet::open(&path, genesis).unwrap();
        assert_eq!(opened.keys().default_address().unwrap(), address);
        let debug = format!("{opened:?}");
        drop(opened);
        assert!(
            matches!(
                Wallet::create(&path, &sk(2), genesis, &mut rng),
                Err(Error::WrongWallet)
            ),
            "no overwrite"
        );
        assert_eq!(debug, "Wallet(<unlocked>)");
    }

    #[cfg(unix)]
    #[test]
    fn wallet_permissions_are_private_even_with_a_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "RHOMBUS_WALLET_PERMISSION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Change umask in an isolated child, never in the multithreaded
            // test process. Use positional arguments rather than shell text.
            let result = std::process::Command::new("sh")
                .args(["-c", "umask 000; exec \"$@\"", "wallet-permission-test"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "wallet::tests::wallet_permissions_are_private_even_with_a_permissive_umask",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "child failed: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        // Verify the handle is private before redb or a key ever reaches it.
        let file = open_wallet_file(&path, true).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(file.metadata().unwrap().len(), 0);
        drop(file);
        let mut rng = ChaCha20Rng::seed_from_u64(7101);
        let key = sk(7101);
        let wallet = Wallet::create(&path, &key, BlockHash::ZERO, &mut rng).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(wallet.keys().spending_key().to_bytes(), key.to_bytes());
        drop(wallet);

        // Also exercise creation without an already-existing empty file.
        let new_path = dir.path().join("new.redb");
        let wallet = Wallet::create(&new_path, &key, BlockHash::ZERO, &mut rng).unwrap();
        assert_eq!(
            std::fs::metadata(&new_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(wallet);
    }

    #[cfg(unix)]
    #[test]
    fn opening_an_existing_wallet_repairs_broad_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(7102);
        let key = sk(7102);
        drop(Wallet::create(&path, &key, BlockHash::ZERO, &mut rng).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let wallet = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(wallet.keys().spending_key().to_bytes(), key.to_bytes());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(wallet);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Wallet::create(&path, &sk(7103), BlockHash::ZERO, &mut rng),
            Err(Error::WrongWallet)
        ));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let wallet = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(wallet.keys().spending_key().to_bytes(), key.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn wallet_paths_refuse_symlinks_without_changing_the_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"not a wallet").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("wallet.redb");
        symlink(&target, &link).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(7104);
        assert!(Wallet::create(&link, &sk(7104), BlockHash::ZERO, &mut rng).is_err());
        assert!(Wallet::open(&link, BlockHash::ZERO).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"not a wallet");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn opening_a_missing_wallet_does_not_create_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        assert!(matches!(
            Wallet::open(&path, BlockHash::ZERO),
            Err(Error::Io(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    // One persisted chain exercises scanning, spending, rollback, and reopening.
    #[allow(clippy::too_many_lines)]
    fn scanning_finds_coins_persists_records_and_detects_spends() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let other_keys = WalletKeys::from_spending_key(sk(4)).unwrap();
        let genesis = BlockHash::from_bytes([2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");

        let owner = WalletKeys::from_spending_key(sk(3)).unwrap();
        let b0 = coinbase_block(&mut rng, &other_keys, BlockHash::ZERO, 0, 5);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 1_000_000_000);
        {
            let wallet = Wallet::create(&path, &sk(3), genesis, &mut rng).unwrap();
            assert_eq!(wallet.scan(&b0).unwrap(), ScanReport { found: 0, spent: 0 });
            assert!(matches!(
                wallet.scan(&b0),
                Err(Error::OutOfOrder {
                    expected: 1,
                    got: 0
                })
            ));
            assert_eq!(wallet.scan(&b1).unwrap(), ScanReport { found: 1, spent: 0 });
            assert_eq!(wallet.balance().unwrap(), 1_000_000_000);
            assert_eq!(wallet.tree_size().unwrap(), 4);
            let position = wallet.unspent().unwrap()[0].position;
            let nullifier = wallet.unspent().unwrap()[0].nullifier;
            assert_eq!(indexed_position(&wallet, &nullifier), Some(position));

            // Simulate a wallet created before the derived index existed.
            let tx = wallet.db.begin_write().unwrap();
            tx.open_table(COINS_BY_NULLIFIER)
                .unwrap()
                .retain(|_, _| false)
                .unwrap();
            tx.open_table(META)
                .unwrap()
                .remove(COIN_INDEX_VERSION)
                .unwrap();
            tx.commit().unwrap();
        }
        let wallet = Wallet::open(&path, genesis).unwrap();
        assert_eq!(wallet.next_height().unwrap(), 2);
        assert_eq!(wallet.scanned_hash(1).unwrap(), Some(b1.hash()));
        let coin = &wallet.unspent().unwrap()[0];
        let original_nullifier = coin.nullifier;
        assert_eq!(
            indexed_position(&wallet, &original_nullifier),
            Some(coin.position)
        );

        let (path_to_coin, anchor) = wallet.witness(coin.position).unwrap();
        let mut b = Builder::new(anchor);
        b.add_spend(SpendInfo::new(sk(3), coin.coin.clone(), path_to_coin))
            .unwrap();
        b.add_output(OutputInfo::new(
            other_keys.default_address().unwrap(),
            RawCoin::from_raw(1_000).unwrap(),
            None,
        ))
        .unwrap();
        let fee = Transaction::default_fee_for_actions(2).unwrap();
        let change = 1_000_000_000 - 1_000 - fee.raw();
        b.add_output(OutputInfo::new(
            owner.default_address().unwrap(),
            RawCoin::from_raw(change).unwrap(),
            None,
        ))
        .unwrap();
        let spend = b.build_with_fee(fee, pk(), BRANCH, &mut rng).unwrap();
        let mut operation = wallet.add_operation(None, 1, 0).unwrap();
        operation.status = OperationStatus::Confirmed {
            txid: spend.txid(),
            height: 2,
        };
        operation.locked = vec![coin.position];
        operation.transaction = Some(spend.to_vec());
        wallet.put_operation(&operation).unwrap();
        let mut retained = wallet.add_operation(None, 1, 0).unwrap();
        retained.status = OperationStatus::Confirmed {
            txid: b1.transactions()[0].txid(),
            height: 1,
        };
        wallet.put_operation(&retained).unwrap();
        let mut header = empty_header(2, b1.hash(), anchor);
        header.tx_root = protocol::block::tx_root([spend.txid()]);
        let b2 = Block::new(header, vec![spend]);
        let position = coin.position;
        let unspent_record = raw_coin(&wallet, position);
        assert_eq!(wallet.scan(&b2).unwrap(), ScanReport { found: 1, spent: 1 });
        assert_eq!(wallet.balance().unwrap(), change);
        let coins_after_spend = wallet.coins().unwrap();
        assert_eq!(coins_after_spend.len(), 2);
        let change_coin = coins_after_spend
            .iter()
            .find(|coin| coin.position != position)
            .unwrap();
        let change_nullifier = change_coin.nullifier;
        assert_eq!(
            indexed_position(&wallet, &change_nullifier),
            Some(change_coin.position)
        );
        assert_eq!(
            indexed_position(&wallet, &original_nullifier),
            Some(position)
        );
        let spent_record = raw_coin(&wallet, position);

        wallet.rollback_to(1).unwrap();
        let pending = wallet.operation(operation.id).unwrap();
        assert_eq!(
            pending.status,
            OperationStatus::Submitted {
                txid: operation.status.txid().unwrap(),
                built_at: 2,
            }
        );
        assert_eq!(pending.transaction, operation.transaction);
        assert_eq!(wallet.locked_positions().unwrap(), vec![position]);
        assert_eq!(wallet.operation(retained.id).unwrap(), retained);
        let restored_record = raw_coin(&wallet, position);
        assert!(!unspent_record.is_empty());
        assert!(!spent_record.is_empty());
        assert!(!restored_record.is_empty());
        assert_eq!(wallet.balance().unwrap(), 1_000_000_000);
        assert_eq!(wallet.tree_size().unwrap(), 4);
        assert_eq!(wallet.coins().unwrap().len(), 1);
        assert_eq!(
            indexed_position(&wallet, &original_nullifier),
            Some(position)
        );
        assert_eq!(indexed_position(&wallet, &change_nullifier), None);
        wallet.rollback_to(5).unwrap();
        assert_eq!(
            wallet.next_height().unwrap(),
            2,
            "rollback above the tip is a no-op"
        );
        drop(wallet);
        let reopened = Wallet::open(&path, genesis).unwrap();
        assert_eq!(reopened.operation(operation.id).unwrap(), pending);
        assert_eq!(reopened.locked_positions().unwrap(), vec![position]);
    }

    #[test]
    fn compact_scanning_finds_the_same_coins_and_tree_as_full_scanning() {
        use protocol::compact::CompactBlock;

        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let owner = WalletKeys::from_spending_key(sk(11)).unwrap();
        let other = WalletKeys::from_spending_key(sk(12)).unwrap();
        let b0 = coinbase_block(&mut rng, &other, BlockHash::ZERO, 0, 5);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 1_000_000_000);

        let (_full_dir, full) = temp_wallet(&sk(11), BlockHash::ZERO, &mut rng);
        full.scan(&b0).unwrap();
        full.scan(&b1).unwrap();

        let (_light_dir, light) = temp_wallet(&sk(11), BlockHash::ZERO, &mut rng);
        assert_eq!(
            light
                .scan_compact(&CompactBlock::from_block(&b0).unwrap())
                .unwrap(),
            ScanReport { found: 0, spent: 0 }
        );
        assert_eq!(
            light
                .scan_compact(&CompactBlock::from_block(&b1).unwrap())
                .unwrap(),
            ScanReport { found: 1, spent: 0 }
        );

        assert_eq!(light.balance().unwrap(), full.balance().unwrap());
        assert_eq!(light.tree_size().unwrap(), full.tree_size().unwrap());
        let (lp, la) = light.witness(light.unspent().unwrap()[0].position).unwrap();
        let (fp, fa) = full.witness(full.unspent().unwrap()[0].position).unwrap();
        assert_eq!(la, fa, "same anchor");
        assert_eq!(lp, fp, "same witness");

        light
            .scan_compact(&CompactBlock::from_block(&b1).unwrap())
            .unwrap_err();
    }

    #[test]
    fn file_wallet_witnesses_match_the_naive_tree() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (_dir, wallet) = temp_wallet(&sk(5), BlockHash::ZERO, &mut rng);
        let owner = WalletKeys::from_spending_key(sk(5)).unwrap();
        let other = WalletKeys::from_spending_key(sk(6)).unwrap();
        assert!(matches!(wallet.anchor(), Err(Error::Corrupt(_))));
        let b0 = coinbase_block(&mut rng, &owner, BlockHash::ZERO, 0, 7);
        let b1 = coinbase_block(&mut rng, &other, b0.hash(), 1, 8);
        let b2 = coinbase_block(&mut rng, &owner, b1.hash(), 2, 9);
        let mut naive = crypto::merkle::MerkleTree::new();
        for block in [&b0, &b1, &b2] {
            wallet.scan(block).unwrap();
            for leaf in scan_block(&owner, block, &tree_transactions(block).unwrap(), 0)
                .unwrap()
                .leaves
            {
                naive.append(leaf).unwrap();
            }
        }
        let coins = wallet.unspent().unwrap();
        assert_eq!(coins.len(), 2);
        let positions: Vec<u64> = coins.iter().map(|n| n.position).collect();
        let (paths, anchor) = wallet.witnesses(&positions).unwrap();
        assert_eq!(anchor, Anchor::from_base(naive.root()));
        assert_eq!(anchor, wallet.anchor().unwrap());
        for (coin, path) in coins.iter().zip(&paths) {
            assert_eq!(path.root(coin.coin.cmx().unwrap().inner()), naive.root());
            assert_eq!(*path, naive.path(coin.position).unwrap());
        }
        assert!(matches!(wallet.witness(99), Err(Error::NoWitness(99))));
        assert_eq!(wallet.tree_size().unwrap(), 6);

        // Rolling back keeps the older witness valid against the older root.
        wallet.rollback_to(0).unwrap();
        let mut short = crypto::merkle::MerkleTree::new();
        for leaf in scan_block(&owner, &b0, &tree_transactions(&b0).unwrap(), 0)
            .unwrap()
            .leaves
        {
            short.append(leaf).unwrap();
        }
        let (path, anchor) = wallet.witness(positions[0]).unwrap();
        assert_eq!(anchor, Anchor::from_base(short.root()));
        assert_eq!(path, short.path(positions[0]).unwrap());
        assert_eq!(wallet.tree_size().unwrap(), 2);
    }

    #[test]
    fn rotation_receipts_match_full_compact_and_survive_reorg_and_reopen() {
        let mut rng = ChaCha20Rng::seed_from_u64(7300);
        let key = sk(7300);
        let (dir, full) = temp_wallet(&key, BlockHash::ZERO, &mut rng);
        let (_compact_dir, compact) = temp_wallet(&key, BlockHash::ZERO, &mut rng);
        let initial = full.current_receive_address().unwrap().unwrap();
        let empty = Block::new(
            empty_header(0, BlockHash::ZERO, Anchor::from_base(pallas::Base::from(0))),
            vec![],
        );
        let paid = coinbase_block(&mut rng, full.keys(), empty.hash(), 1, 100);
        let old_paid_again = coinbase_block(&mut rng, full.keys(), paid.hash(), 2, 50);
        for (wallet, light) in [(&full, false), (&compact, true)] {
            for block in [&empty, &paid] {
                if light {
                    wallet
                        .scan_compact(&CompactBlock::from_block(block).unwrap())
                        .unwrap();
                } else {
                    wallet.scan(block).unwrap();
                }
            }
            let current = wallet.current_receive_address().unwrap().unwrap();
            assert_eq!(current.0, 1);
            assert_ne!(current.1, initial.1);
            assert_ne!(current.1.kem_key(), initial.1.kem_key());
            if light {
                wallet
                    .scan_compact(&CompactBlock::from_block(&old_paid_again).unwrap())
                    .unwrap();
            } else {
                wallet.scan(&old_paid_again).unwrap();
            }
            assert_eq!(wallet.balance().unwrap(), 150);
            assert_eq!(
                wallet.current_receive_address().unwrap(),
                Some(current.clone())
            );
            wallet.rollback_to(0).unwrap();
            if light {
                wallet
                    .scan_compact(&CompactBlock::from_block(&paid).unwrap())
                    .unwrap();
            } else {
                wallet.scan(&paid).unwrap();
            }
            assert_eq!(wallet.current_receive_address().unwrap(), Some(current));
            assert_eq!(wallet.address_scan_range().unwrap().end, 2);
        }
        let current = full.current_receive_address().unwrap();
        drop(full);
        let reopened = Wallet::open(dir.path().join("wallet.redb"), BlockHash::ZERO).unwrap();
        assert_eq!(reopened.current_receive_address().unwrap(), current);
        assert_eq!(reopened.balance().unwrap(), 100);
    }

    #[test]
    fn rotation_send_builds_use_distinct_change_and_keep_all_keys_scannable() {
        let mut rng = ChaCha20Rng::seed_from_u64(7301);
        let (_dir, wallet) = temp_wallet(&sk(7301), BlockHash::ZERO, &mut rng);
        let funding = coinbase_block(&mut rng, wallet.keys(), BlockHash::ZERO, 0, 1_000_000_000);
        wallet.scan(&funding).unwrap();
        let before = wallet.current_receive_address().unwrap().unwrap();
        let recipient = WalletKeys::from_spending_key(sk(8301))
            .unwrap()
            .default_address()
            .unwrap();
        let payment = Payment {
            recipient,
            amount: RawCoin::from_raw(10_000).unwrap(),
        };
        let mut changes = Vec::new();
        let mut built = Vec::new();
        for _ in 0..2 {
            let transaction =
                crate::spend::build_payment(&wallet, payment.clone(), pk(), BRANCH, &mut rng)
                    .unwrap();
            let block = Block::new(
                empty_header(1, funding.hash(), Anchor::from_base(pallas::Base::from(1))),
                vec![transaction],
            );
            let scan = scan_block_with_keys(
                wallet.keys(),
                &wallet.scanning_keys().unwrap(),
                &block,
                &tree_transactions(&block).unwrap(),
                wallet.tree_size().unwrap(),
            )
            .unwrap();
            assert_eq!(scan.found.len(), 1);
            let owned = scan.found.first().unwrap();
            let change = wallet
                .keys
                .address_for_coin(&owned.coin, owned.legacy_address)
                .unwrap();
            let current = wallet.current_receive_address().unwrap().unwrap();
            assert_ne!(change, before.1);
            assert_ne!(change, current.1);
            assert_ne!(change, wallet.keys.default_address().unwrap());
            assert!(wallet.scans_address(&change).unwrap());
            changes.push(change);
            built.push(block);
        }
        assert_ne!(changes.first(), changes.get(1));
        let current = wallet.current_receive_address().unwrap();
        wallet.scan(built.first().unwrap()).unwrap();
        assert_eq!(
            wallet.current_receive_address().unwrap(),
            current,
            "confirming change must not rotate again"
        );
    }

    #[test]
    fn rotation_restores_and_migrated_wallets_choose_unallocated_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(7302);
        let wallet = Wallet::restore(&path, &sk(7302), BlockHash::ZERO, 42, &mut rng).unwrap();
        assert_eq!(wallet.current_receive_address().unwrap().unwrap().0, 43);
        let tx = wallet.db.begin_write().unwrap();
        tx.open_table(META)
            .unwrap()
            .remove(CURRENT_RECEIVE_ADDRESS)
            .unwrap();
        tx.commit().unwrap();
        drop(wallet);
        let reopened = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(reopened.current_receive_address().unwrap().unwrap().0, 44);
        assert_eq!(reopened.address_scan_range().unwrap().end, 45);
    }

    #[test]
    fn rotation_parallel_readers_reserve_only_one_current_address() {
        let mut rng = ChaCha20Rng::seed_from_u64(7303);
        let (_dir, wallet) = temp_wallet(&sk(7303), BlockHash::ZERO, &mut rng);
        wallet.reserve_send_address(false).unwrap();
        let results = std::thread::scope(|scope| {
            (0..8)
                .map(|_| scope.spawn(|| wallet.current_receive_address().unwrap().unwrap()))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(results.iter().all(|result| Some(result) == results.first()));
        assert_eq!(wallet.address_scan_range().unwrap().end, 2);
    }

    #[test]
    fn rotation_exhaustion_does_not_block_receipts_or_partially_reserve_change() {
        let mut rng = ChaCha20Rng::seed_from_u64(7304);
        let (_dir, wallet) = temp_wallet(&sk(7304), BlockHash::ZERO, &mut rng);
        let last = MAX_SCAN_ADDRESSES.checked_sub(1).unwrap();
        // Keep this fixture's scan range to one key at the allocation boundary.
        let tx = wallet.db.begin_write().unwrap();
        {
            let mut meta = tx.open_table(META).unwrap();
            meta.insert(ADDRESS_KEY_START, last.to_le_bytes().as_slice())
                .unwrap();
            meta.insert(NEXT_ADDRESS, MAX_SCAN_ADDRESSES.to_le_bytes().as_slice())
                .unwrap();
            meta.insert(CURRENT_RECEIVE_ADDRESS, last.to_le_bytes().as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
        let current = wallet.current_receive_address().unwrap().unwrap();
        assert!(wallet.reserve_send_address(true).is_err());
        assert_eq!(
            wallet.current_receive_address().unwrap(),
            Some(current.clone())
        );
        let mut builder = Builder::new(Anchor::from_base(pallas::Base::from(0)));
        builder
            .add_output(OutputInfo::new(
                current.1,
                RawCoin::from_raw(100).unwrap(),
                None,
            ))
            .unwrap();
        let payment = builder
            .build_coinbase(pk(), RawCoin::from_raw(100).unwrap(), BRANCH, &mut rng)
            .unwrap();
        let block = Block::new(
            empty_header(0, BlockHash::ZERO, Anchor::from_base(pallas::Base::from(0))),
            vec![payment],
        );
        assert_eq!(
            wallet
                .scan_compact(&CompactBlock::from_block(&block).unwrap())
                .unwrap()
                .found,
            1
        );
        assert_eq!(wallet.balance().unwrap(), 100);
        assert_eq!(wallet.current_receive_address().unwrap(), None);
        assert_eq!(wallet.address_scan_range().unwrap().end, MAX_SCAN_ADDRESSES);
    }

    #[test]
    fn rotation_scan_failure_rolls_back_retirement_and_rejects_corrupt_current() {
        let mut rng = ChaCha20Rng::seed_from_u64(7305);
        let (dir, wallet) = temp_wallet(&sk(7305), BlockHash::ZERO, &mut rng);
        let current = wallet.current_receive_address().unwrap();
        let block = coinbase_block(&mut rng, wallet.keys(), BlockHash::ZERO, 0, 100);
        let tree = tree_transactions(&block).unwrap();
        assert!(wallet
            .apply(0, block.hash(), |keys, position| {
                let mut scan = scan_block_with_keys(wallet.keys(), keys, &block, &tree, position)?;
                scan.found.push(scan.found.first().unwrap().clone());
                Ok(scan)
            })
            .is_err());
        assert_eq!(wallet.current_receive_address().unwrap(), current);
        assert_eq!(wallet.balance().unwrap(), 0);
        assert_eq!(wallet.next_height().unwrap(), 0);
        let tx = wallet.db.begin_write().unwrap();
        tx.open_table(META)
            .unwrap()
            .insert(CURRENT_RECEIVE_ADDRESS, 1u64.to_le_bytes().as_slice())
            .unwrap();
        tx.commit().unwrap();
        drop(wallet);
        assert!(matches!(
            Wallet::open(dir.path().join("wallet.redb"), BlockHash::ZERO),
            Err(Error::Corrupt(
                "receive address exceeds allocated key range"
            ))
        ));
    }

    #[test]
    fn addresses_are_handed_out_with_labels_and_map_back() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let (_dir, wallet) = temp_wallet(&sk(11), BlockHash::ZERO, &mut rng);
        let (first, a) = wallet.new_address("alice").unwrap();
        let (second, b) = wallet.new_address("bob").unwrap();
        assert_eq!((first, second), (1, 2));
        assert_ne!(a, b);
        assert_ne!(a.kem_key(), b.kem_key());
        let listed = wallet.addresses().unwrap();
        assert_eq!(listed.len(), 3, "default plus two");
        assert_eq!(listed[0].0, 0);
        assert_eq!(listed[1], (1, a, "alice".to_string()));
        assert_eq!(listed[2], (2, b.clone(), "bob".to_string()));
        assert_eq!(wallet.address_index_of(&b), Some(2));
        assert_eq!(
            wallet.address_index_of(&wallet.keys().default_address().unwrap()),
            Some(0)
        );
        let other = WalletKeys::from_spending_key(sk(12)).unwrap();
        assert_eq!(
            wallet.address_index_of(&other.default_address().unwrap()),
            None
        );
    }

    #[test]
    fn legacy_wallet_migration_preserves_addresses_and_reopens_new_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(7200);
        let (dir, wallet) = temp_wallet(&sk(7200), BlockHash::ZERO, &mut rng);
        let path = dir.path().join("wallet.redb");
        wallet.new_address("legacy label").unwrap();
        let old_default = wallet.keys.legacy_address(0u64.into()).unwrap();
        let old_issued = wallet.keys.legacy_address(1u64.into()).unwrap();
        // Recreate metadata of a pre-upgrade wallet without changing keys,
        // labels or the persisted allocation counter.
        let tx = wallet.db.begin_write().unwrap();
        {
            let mut meta = tx.open_table(META).unwrap();
            meta.remove(ADDRESS_KEY_SCHEME).unwrap();
            meta.remove(ADDRESS_KEY_START).unwrap();
        }
        tx.commit().unwrap();
        drop(wallet);

        let wallet = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(wallet.keys.default_address().unwrap(), old_default);
        assert_eq!(
            wallet.addresses().unwrap()[1],
            (1, old_issued, "legacy label".into())
        );
        assert_eq!(
            wallet.address_scan_range().unwrap(),
            AddressScanRange { start: 2, end: 2 }
        );
        let before = wallet.scanning_keys().unwrap();
        let (index, fresh) = wallet.new_address("new label").unwrap();
        assert_eq!(index, 2);
        assert_ne!(fresh.kem_key(), old_default.kem_key());
        let after = wallet.scanning_keys().unwrap();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "new address invalidates scan context"
        );
        assert!(Arc::ptr_eq(&after, &wallet.scanning_keys().unwrap()));
        drop(wallet);

        let reopened = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(reopened.keys.default_address().unwrap(), old_default);
        assert_eq!(
            reopened.addresses().unwrap()[2],
            (2, fresh, "new label".into())
        );
        assert_eq!(
            reopened.address_scan_range().unwrap(),
            AddressScanRange { start: 2, end: 3 }
        );
    }

    #[test]
    fn recovery_range_is_persistent_and_reserved_before_issuing_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(7201);
        let wallet = Wallet::restore(&path, &sk(7201), BlockHash::ZERO, 42, &mut rng).unwrap();
        assert_eq!(
            wallet.address_scan_range().unwrap(),
            AddressScanRange { start: 0, end: 43 }
        );
        drop(wallet);
        let wallet = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(wallet.new_address("after recovery").unwrap().0, 43);
        assert_eq!(wallet.address_scan_range().unwrap().end, 44);
    }

    #[test]
    fn unsupported_scheme_and_unrecoverable_ranges_fail_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-restore.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(7202);
        for last in [MAX_SCAN_ADDRESSES, u64::MAX] {
            assert!(Wallet::restore(&path, &sk(7202), BlockHash::ZERO, last, &mut rng).is_err());
            assert!(
                !path.exists(),
                "range validation must precede file creation"
            );
        }
        let wallet = Wallet::restore(
            &path,
            &sk(7202),
            BlockHash::ZERO,
            MAX_SCAN_ADDRESSES - 1,
            &mut rng,
        )
        .unwrap();
        assert!(wallet.new_address("over limit").is_err());
        assert_eq!(wallet.address_scan_range().unwrap().end, MAX_SCAN_ADDRESSES);
        let tx = wallet.db.begin_write().unwrap();
        tx.open_table(META)
            .unwrap()
            .insert(ADDRESS_KEY_SCHEME, [99u8].as_slice())
            .unwrap();
        tx.commit().unwrap();
        drop(wallet);
        assert!(matches!(
            Wallet::open(&path, BlockHash::ZERO),
            Err(Error::Corrupt("unsupported address key scheme"))
        ));
    }

    #[test]
    fn versioned_wallet_does_not_guess_a_missing_allocation_counter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(7203);
        let wallet = Wallet::restore(&path, &sk(7203), BlockHash::ZERO, 42, &mut rng).unwrap();
        let tx = wallet.db.begin_write().unwrap();
        tx.open_table(META).unwrap().remove(NEXT_ADDRESS).unwrap();
        tx.commit().unwrap();
        drop(wallet);
        assert!(matches!(
            Wallet::open(&path, BlockHash::ZERO),
            Err(Error::Corrupt("missing address allocation counter"))
        ));
    }

    #[test]
    fn migrated_high_legacy_indices_remain_scannable_but_cannot_issue_new_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(7204);
        let (dir, wallet) = temp_wallet(&sk(7204), BlockHash::ZERO, &mut rng);
        let path = dir.path().join("wallet.redb");
        let tx = wallet.db.begin_write().unwrap();
        {
            let mut meta = tx.open_table(META).unwrap();
            meta.remove(ADDRESS_KEY_SCHEME).unwrap();
            meta.remove(ADDRESS_KEY_START).unwrap();
            meta.insert(NEXT_ADDRESS, 5001u64.to_le_bytes().as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
        drop(wallet);
        let wallet = Wallet::open(&path, BlockHash::ZERO).unwrap();
        assert_eq!(wallet.scanning_keys().unwrap().candidate_count(), 1);
        assert!(wallet
            .scans_address(&wallet.keys.legacy_address(5000u64.into()).unwrap())
            .unwrap());
        assert!(!wallet
            .scans_address(&wallet.keys.address(5000u64.into()).unwrap())
            .unwrap());
        assert!(wallet.new_address("outside recovery range").is_err());
    }

    #[test]
    fn recovery_finds_legacy_and_new_payments_only_within_declared_range() {
        let mut rng = ChaCha20Rng::seed_from_u64(7205);
        let key = sk(7205);
        let keys = WalletKeys::from_spending_key(key.clone()).unwrap();
        let mut builder = Builder::new(Anchor::from_base(pallas::Base::from(0u64)));
        builder
            .add_output(OutputInfo::new(
                keys.address(42u64.into()).unwrap(),
                RawCoin::from_raw(19).unwrap(),
                None,
            ))
            .unwrap();
        builder
            .add_output(OutputInfo::new(
                keys.legacy_address(5000u64.into()).unwrap(),
                RawCoin::from_raw(11).unwrap(),
                None,
            ))
            .unwrap();
        let tx = builder
            .build_coinbase(pk(), RawCoin::from_raw(30).unwrap(), BRANCH, &mut rng)
            .unwrap();
        let block = Block::new(empty_header(0, BlockHash::ZERO, *tx.anchor()), vec![tx]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.redb");
        drop(Wallet::restore(&path, &key, BlockHash::ZERO, 42, &mut rng).unwrap());
        let full = Wallet::open(&path, BlockHash::ZERO).unwrap();
        full.scan(&block).unwrap();
        assert_eq!(full.balance().unwrap(), 30);
        let compact = Wallet::restore(
            dir.path().join("compact.redb"),
            &key,
            BlockHash::ZERO,
            42,
            &mut rng,
        )
        .unwrap();
        compact
            .scan_compact(&CompactBlock::from_block(&block).unwrap())
            .unwrap();
        assert_eq!(compact.balance().unwrap(), 30);
        let short = Wallet::restore(
            dir.path().join("short.redb"),
            &key,
            BlockHash::ZERO,
            41,
            &mut rng,
        )
        .unwrap();
        short.scan(&block).unwrap();
        assert_eq!(
            short.balance().unwrap(),
            11,
            "legacy detection does not depend on index range"
        );
        assert!(!short
            .scans_address(&keys.address(42u64.into()).unwrap())
            .unwrap());
    }

    #[test]
    fn operations_persist_and_lock_coins_while_pending() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let (_dir, wallet) = temp_wallet(&sk(13), BlockHash::ZERO, &mut rng);
        let payment = Payment {
            recipient: wallet.keys().default_address().unwrap(),
            amount: RawCoin::from_raw(5).unwrap(),
        };
        let mut op = wallet
            .add_operation(Some(payment.clone()), 3, 1_000)
            .unwrap();
        assert_eq!(op.id, 1);
        assert_eq!(wallet.add_operation(Some(payment), 3, 1_001).unwrap().id, 2);
        op.locked = vec![4, 9];
        op.status = crate::operations::OperationStatus::Proving;
        wallet.put_operation(&op).unwrap();
        assert_eq!(wallet.operation(1).unwrap(), op);
        assert_eq!(wallet.operations().unwrap().len(), 2);
        assert_eq!(wallet.locked_positions().unwrap(), vec![4, 9]);
        op.status = crate::operations::OperationStatus::Cancelled;
        wallet.put_operation(&op).unwrap();
        assert_eq!(wallet.locked_positions().unwrap().len(), 0);
        assert!(matches!(wallet.operation(7), Err(Error::NoOperation(7))));
    }

    #[test]
    fn operation_updates_cannot_overwrite_a_cancellation_or_a_prover_claim() {
        let mut rng = ChaCha20Rng::seed_from_u64(16);
        let (_dir, wallet) = temp_wallet(&sk(16), BlockHash::ZERO, &mut rng);
        let queued = wallet.add_operation(None, 1, 0).unwrap();
        let mut cancelled = queued.clone();
        cancelled.status = OperationStatus::Cancelled;
        let mut building = queued.clone();
        building.status = OperationStatus::Building;
        assert!(wallet
            .compare_and_swap_operation(&queued, &cancelled)
            .unwrap());
        assert!(!wallet
            .compare_and_swap_operation(&queued, &building)
            .unwrap());
        assert_eq!(wallet.operation(queued.id).unwrap(), cancelled);

        wallet.put_operation(&queued).unwrap();
        assert!(wallet
            .compare_and_swap_operation(&queued, &building)
            .unwrap());
        assert!(!wallet
            .compare_and_swap_operation(&queued, &cancelled)
            .unwrap());
        assert_eq!(wallet.operation(queued.id).unwrap(), building);
        cancelled.id = 999;
        assert!(wallet
            .compare_and_swap_operation(&building, &cancelled)
            .is_err());
        assert!(!wallet
            .compare_and_swap_operation(&cancelled, &cancelled)
            .unwrap());
    }

    #[test]
    fn a_mined_reward_is_found_in_its_block() {
        let mut rng = ChaCha20Rng::seed_from_u64(61);
        let owner = WalletKeys::from_spending_key(sk(61)).unwrap();
        let (_dir, wallet) = temp_wallet(&sk(61), BlockHash::ZERO, &mut rng);
        let b0 = coinbase_block(&mut rng, &owner, BlockHash::ZERO, 0, 7);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 8);
        // Genesis has no coinbase; subsequent rewards enter immediately.
        wallet.scan(&b0).unwrap();
        let size_before = wallet.tree_size().unwrap();
        wallet.scan(&b1).unwrap();
        assert_eq!(wallet.balance().unwrap(), 7 + 8, "genesis has no coinbase");
        let reward = wallet
            .unspent()
            .unwrap()
            .into_iter()
            .find(|n| n.coin.value().raw() == 8)
            .unwrap();
        let leaves = size_before..size_before + b1.transactions()[0].actions().len() as u64;
        assert!(
            leaves.contains(&reward.position),
            "one of the leaves block 1 added"
        );
        assert_eq!(
            (reward.height, reward.txid),
            (1, Some(b1.transactions()[0].txid()))
        );

        wallet.rollback_to(0).unwrap();
        assert_eq!(wallet.balance().unwrap(), 7, "a rollback removes block 1");
    }
}
