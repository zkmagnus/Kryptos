//! The chain database.
//!
//! Tables:
//!
//! | table | key | value |
//! |---|---|---|
//! | `blocks` | block hash | block bytes |
//! | `chainwork` | block hash | cumulative work, 32-byte big-endian |
//! | `heights` | height | block hash |
//! | `nullifiers` | nullifier | height it was spent at |
//! | `frontiers` | height | commitment tree after that block |
//! | `meta` | name | tip hash |
//!
//! [`Store::apply`] and [`Store::revert`] each run in one write
//! transaction, so the tables never disagree after a crash.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crypto::encoding::{base_from_bytes, Encoded};
use protocol::block::{header_len_for_version, Block, BlockHash, BlockHeader};
use protocol::bytes::Encodable;
use protocol::consensus::next_height;
use protocol::header_tree::{self, mountain_for_index, HeaderFrontier, HeaderMerklePath};
use protocol::nullifier::Nullifier;
use protocol::transaction::{Anchor, Transaction, TxId};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::nullifier::{self, NodeRecord, NullifierPath, NullifierTransition};
use crate::tree::CommitmentTree;
use crate::{Error, Result};

const BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blocks");
/// Header-only entries imported from a trusted snapshot. Full blocks remain
/// in `BLOCKS`; this table is the authoritative header source when a body is
/// intentionally absent.
const HEADERS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("headers");
const CHAINWORK: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("chainwork");
const HEIGHTS: TableDefinition<u32, &[u8; 32]> = TableDefinition::new("heights");
const NULLIFIERS: TableDefinition<&[u8; 32], u32> = TableDefinition::new("nullifiers");
/// Block hash to `canonical root || LE64 set size` for every retained branch.
const NULLIFIER_ROOTS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("nullifier_roots");
/// Content-addressed nullifier sparse-Merkle internal nodes.
const NULLIFIER_NODES: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("nullifier_nodes");
/// Block hash to cumulative commitment count, including side branches.
const COMMITMENT_COUNTS: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("commitment_counts");
/// Block hash to commitment-tree frontier, including side branches.
const BRANCH_FRONTIERS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("branch_frontiers");
const FRONTIERS: TableDefinition<u32, &[u8]> = TableDefinition::new("frontiers");
/// Block hash to the header frontier after that block, independently per fork.
const HEADER_FRONTIERS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("header_frontiers");
/// Content-addressed header-tree internal nodes, encoded as left || right.
const HEADER_NODES: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("header_nodes");
const META: TableDefinition<&str, &[u8; 32]> = TableDefinition::new("meta");
/// Transaction id to its location, `LE32(height) || LE32(index)`.
const TXIDS: TableDefinition<&[u8; 32], &[u8; 8]> = TableDefinition::new("txids");

/// Meta key of the tip hash.
const TIP: &str = "tip";
/// The immutable network identifier used as the nullifier-tree domain.
const CHAIN_ID: &str = "chain_id";
/// Checkpoint hash that anchors an installed snapshot.
const SNAPSHOT_BASE: &str = "snapshot_base";
/// Meta key of the consensus rules digest the store was built under.
const RULES: &str = "rules";
/// Meta key of the on-disk layout version.
const SCHEMA: &str = "schema";
/// The on-disk layout this code writes and reads. Bumped whenever a table
/// is added or changed; an older store is refused rather than served with
/// tables it never filled.
pub const SCHEMA_VERSION: u32 = 1;

/// A locally validated checkpoint used to bind an atomic snapshot install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotCheckpoint {
    /// Checkpoint height.
    pub height: u32,
    /// Checkpoint block hash.
    pub hash: BlockHash,
    /// Validated cumulative work, big-endian U256.
    pub work: [u8; 32],
    /// Composite state root committed by its header.
    pub state_root: Anchor,
}

/// One header and retained note-tree frontier from a verified snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// Canonically encoded block header.
    pub header: BlockHeader,
    /// Commitment-tree size after this block.
    pub commitment_count: u64,
    /// Nullifier count after this block.
    pub nullifier_count: u64,
    /// Validated cumulative work after this header, big-endian U256.
    pub chainwork: [u8; 32],
    /// Canonically encoded commitment-tree frontier.
    pub frontier: Vec<u8>,
}

/// Materialized, checkpoint-bound state submitted for atomic installation.
/// The caller must first verify the checkpoint against the configured network
/// profile; storage independently checks all payload roots and linkage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInstall {
    /// Genesis hash / nullifier-tree domain identifier.
    pub chain_id: [u8; 32],
    /// Rules digest expected by the receiving chain.
    pub rules_digest: [u8; 32],
    /// Checkpoint that authenticated this exact snapshot.
    pub checkpoint: SnapshotCheckpoint,
    /// Header-tree prefix immediately before the first retained suffix header.
    pub header_frontier: HeaderFrontier,
    /// Header suffix from which the installed tip can resume validation.
    pub headers: Vec<SnapshotHeader>,
    /// Every spent nullifier, sorted by canonical bytes.
    pub nullifiers: Vec<Nullifier>,
}

/// Whether snapshot installation may replace existing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotInstallMode {
    /// Install only into an empty store or replace its exact genesis-only bootstrap.
    EmptyOnly,
    /// Explicitly replace all existing chain state in one transaction.
    ReplaceExisting,
}

/// The chain tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    /// Height of the tip block.
    pub height: u32,
    /// Hash of the tip block.
    pub hash: BlockHash,
}

/// A block-state violation found against one consistent chain snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStateViolation {
    /// A transaction references an unknown or stale commitment-tree root.
    UnknownOrStaleAnchor,
    /// A transaction spends a nullifier already present on the chain.
    NullifierAlreadySpent,
}

/// The chain database.
#[derive(Clone, Debug)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    /// Opens or creates the database at `path`.
    ///
    /// # Errors
    /// Fails if the file cannot be opened or its tables created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Database::create(path)?)
    }

    fn init(db: Database) -> Result<Self> {
        let tx = db.begin_write()?;
        tx.open_table(BLOCKS)?;
        tx.open_table(HEADERS)?;
        tx.open_table(CHAINWORK)?;
        tx.open_table(HEIGHTS)?;
        tx.open_table(NULLIFIERS)?;
        tx.open_table(NULLIFIER_ROOTS)?;
        tx.open_table(NULLIFIER_NODES)?;
        tx.open_table(COMMITMENT_COUNTS)?;
        tx.open_table(BRANCH_FRONTIERS)?;
        tx.open_table(FRONTIERS)?;
        tx.open_table(HEADER_FRONTIERS)?;
        tx.open_table(HEADER_NODES)?;
        tx.open_table(TXIDS)?;
        {
            let mut meta = tx.open_table(META)?;
            let recorded = meta.get(SCHEMA)?.map(|v| *v.value());
            let fresh = meta.get(TIP)?.is_none();
            match recorded {
                Some(v) if v == schema_bytes() => {}
                None if fresh => {
                    meta.insert(SCHEMA, &schema_bytes())?;
                }
                _ => {
                    return Err(Error::Corrupt(
                        "store layout outdated; delete it and resync",
                    ));
                }
            }
        }
        tx.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Records the original tip and fork before the first reorg mutation.
    /// The journal remains until either the new chain or recovery is complete.
    pub fn begin_reorg(&self, original: BlockHash, fork: BlockHash) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            if meta.get("reorg_original")?.is_some() {
                return Err(Error::Corrupt("unfinished reorganization"));
            }
            meta.insert("reorg_original", original.as_bytes())?;
            meta.insert("reorg_fork", fork.as_bytes())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The unfinished reorg's original tip and fork, if any.
    pub fn pending_reorg(&self) -> Result<Option<(BlockHash, BlockHash)>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        match (meta.get("reorg_original")?, meta.get("reorg_fork")?) {
            (None, None) => Ok(None),
            (Some(original), Some(fork)) => Ok(Some((
                BlockHash::from_bytes(*original.value()),
                BlockHash::from_bytes(*fork.value()),
            ))),
            _ => Err(Error::Corrupt("incomplete reorganization journal")),
        }
    }

    /// Commits completion of a reorg or its recovery.
    pub fn finish_reorg(&self) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            meta.remove("reorg_original")?;
            meta.remove("reorg_fork")?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The current tip, or `None` before genesis.
    ///
    /// # Errors
    /// Fails on a read error or a corrupt height index.
    pub fn tip(&self) -> Result<Option<Tip>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        let Some(hash) = meta.get(TIP)? else {
            return Ok(None);
        };
        let hash = BlockHash::from_bytes(*hash.value());
        let blocks = tx.open_table(BLOCKS)?;
        let header = if let Some(bytes) = blocks.get(hash.as_bytes())? {
            decode_header(bytes.value(), &hash)?
        } else {
            let headers = tx.open_table(HEADERS)?;
            let bytes = headers
                .get(hash.as_bytes())?
                .ok_or(Error::Corrupt("tip header missing"))?;
            decode_header(bytes.value(), &hash)?
        };
        Ok(Some(Tip {
            height: header.height,
            hash,
        }))
    }

    /// Where a transaction is in the main chain: `(height, index)`.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn transaction_location(&self, txid: &TxId) -> Result<Option<(u32, u32)>> {
        let tx = self.db.begin_read()?;
        let txids = tx.open_table(TXIDS)?;
        Ok(txids
            .get(txid.as_bytes())?
            .map(|v| decode_location(*v.value())))
    }

    /// A main-chain transaction with its height and index in the block.
    ///
    /// # Errors
    /// Fails on a read error or an index pointing at a missing block.
    pub fn transaction(&self, txid: &TxId) -> Result<Option<(Transaction, u32, u32)>> {
        let Some((height, index)) = self.transaction_location(txid)? else {
            return Ok(None);
        };
        let hash = self
            .hash_at(height)?
            .ok_or(Error::Corrupt("indexed height missing"))?;
        let block = self
            .block(&hash)?
            .ok_or(Error::Corrupt("indexed block missing"))?;
        let tx = block
            .transactions()
            .get(usize::try_from(index).map_err(|_| Error::Corrupt("index"))?)
            .cloned()
            .ok_or(Error::Corrupt("indexed transaction missing"))?;
        Ok(Some((tx, height, index)))
    }

    /// The digest of the consensus rules this store was built under, if
    /// one was recorded.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn rules_digest(&self) -> Result<Option<[u8; 32]>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta.get(RULES)?.map(|v| *v.value()))
    }

    /// Records the digest of the consensus rules this store is built
    /// under.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn set_rules_digest(&self, digest: &[u8; 32]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            meta.insert(RULES, digest)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Bind this store to its immutable network identifier. An identifier can
    /// only be installed before history; a genesis-only store can be rebound
    /// because it contains no nullifiers and has no state transition history.
    pub fn set_chain_id(&self, chain_id: &[u8; 32]) -> Result<()> {
        let tip = self.tip()?;
        let can_bind_genesis = {
            let read = self.db.begin_read()?;
            let blocks = read.open_table(BLOCKS)?;
            let nullifiers = read.open_table(NULLIFIERS)?;
            let no_nullifiers = nullifiers.is_empty()?;
            match tip {
                None => blocks.is_empty()? && no_nullifiers,
                Some(tip) if tip.height == 0 => {
                    blocks.len()? == 1
                        && blocks.get(tip.hash.as_bytes())?.is_some()
                        && no_nullifiers
                }
                Some(_) => false,
            }
        };
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            let existing = meta.get(CHAIN_ID)?.map(|value| *value.value());
            match existing {
                Some(existing) if existing == *chain_id => return Ok(()),
                Some(_) => return Err(Error::Corrupt("store belongs to another network")),
                None if !can_bind_genesis => {
                    return Err(Error::Corrupt("chain id missing for populated store"));
                }
                None => {
                    meta.insert(CHAIN_ID, chain_id)?;
                }
            }
        }
        if let Some(tip) = tip {
            let roots = tx.open_table(NULLIFIER_ROOTS)?;
            if roots.get(tip.hash.as_bytes())?.is_some() {
                drop(roots);
                let mut roots = tx.open_table(NULLIFIER_ROOTS)?;
                let root_record = encode_nullifier_root(nullifier::empty_root(chain_id), 0);
                roots.insert(tip.hash.as_bytes(), root_record.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Network identifier bound to the nullifier-tree domain. Raw storage
    /// users that have not opened a chain use the all-zero development ID.
    pub fn chain_id(&self) -> Result<[u8; 32]> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta.get(CHAIN_ID)?.map_or([0; 32], |value| *value.value()))
    }

    /// Encoded body size without decoding or allocating its transactions.
    /// Used to reserve network capacity before loading a stored block.
    ///
    /// # Errors
    /// Fails on a database read error.
    pub fn block_encoded_len(&self, hash: &BlockHash) -> Result<Option<usize>> {
        let tx = self.db.begin_read()?;
        let blocks = tx.open_table(BLOCKS)?;
        Ok(blocks
            .get(hash.as_bytes())?
            .map(|bytes| bytes.value().len()))
    }

    /// The stored block header, without decoding or allocating transactions.
    /// The header must match its database key. This is not a body-integrity check;
    /// callers needing transactions must use [`Self::block`].
    ///
    /// # Errors
    /// Fails on a database error, a truncated/malformed header, or a key mismatch.
    pub fn header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>> {
        let tx = self.db.begin_read()?;
        let blocks = tx.open_table(BLOCKS)?;
        if let Some(bytes) = blocks.get(hash.as_bytes())? {
            return Ok(Some(decode_header(bytes.value(), hash)?));
        }
        let headers = tx.open_table(HEADERS)?;
        headers
            .get(hash.as_bytes())?
            .map(|bytes| decode_header(bytes.value(), hash))
            .transpose()
    }

    /// Header-history frontier after a stored block, including retained forks.
    /// The block hash and count are checked against the stored header.
    pub fn header_frontier(&self, hash: &BlockHash) -> Result<Option<HeaderFrontier>> {
        let read = self.db.begin_read()?;
        let frontiers = read.open_table(HEADER_FRONTIERS)?;
        let frontier = frontiers
            .get(hash.as_bytes())?
            .map(|bytes| HeaderFrontier::from_slice(bytes.value()))
            .transpose()?;
        if let Some(frontier) = &frontier {
            if frontier.tip_hash() != Some(*hash) {
                return Err(Error::Corrupt("header frontier tip mismatch"));
            }
            let blocks = read.open_table(BLOCKS)?;
            let header_bytes = blocks
                .get(hash.as_bytes())?
                .map(|value| value.value().to_vec());
            drop(blocks);
            let header_bytes = if let Some(bytes) = header_bytes {
                Some(bytes)
            } else {
                read.open_table(HEADERS)?
                    .get(hash.as_bytes())?
                    .map(|value| value.value().to_vec())
            };
            if let Some(bytes) = header_bytes {
                let header = decode_header(&bytes, hash)?;
                if frontier.count() != u64::from(header.height) + 1 {
                    return Err(Error::Corrupt("header frontier index mismatch"));
                }
                let parent_frontier = if header.height == 0 {
                    HeaderFrontier::empty()
                } else {
                    read.open_table(HEADER_FRONTIERS)?
                        .get(header.prev_hash.as_bytes())?
                        .map(|value| HeaderFrontier::from_slice(value.value()))
                        .transpose()?
                        .ok_or(Error::Corrupt("parent header frontier missing"))?
                };
                if header.version == protocol::consensus::BLOCK_VERSION
                    && header.history_root != parent_frontier.root()
                {
                    return Err(Error::Corrupt("header history root mismatch"));
                }
                let mut expected = parent_frontier;
                expected.append(&header)?;
                if expected != *frontier {
                    return Err(Error::Corrupt("header frontier does not match header"));
                }
            } else if frontier.count() > u64::from(u32::MAX) {
                return Err(Error::Corrupt("header frontier index mismatch"));
            }
        }
        Ok(frontier)
    }

    /// The opaque imported prefix immediately before `first_header`, when
    /// available. It is authenticated by that header's history root and the
    /// snapshot's configured checkpoint; old membership paths may be absent.
    pub fn header_prefix_before(&self, first_header: &BlockHash) -> Result<Option<HeaderFrontier>> {
        let Some(header) = self.header(first_header)? else {
            return Ok(None);
        };
        if header.height == 0 {
            return Ok(Some(HeaderFrontier::empty()));
        }
        let Some(frontier) = self.header_frontier(&header.prev_hash)? else {
            return Ok(None);
        };
        if frontier.count() != u64::from(header.height)
            || frontier.tip_hash() != Some(header.prev_hash)
            || (header.version == protocol::consensus::BLOCK_VERSION
                && frontier.root() != header.history_root)
        {
            return Err(Error::Corrupt(
                "header prefix does not match first suffix header",
            ));
        }
        Ok(Some(frontier))
    }

    /// Checks a child's history commitment against its exact stored parent.
    /// Does not validate PoW, transactions, or canonical-chain membership.
    pub fn check_header_history(&self, header: &BlockHeader) -> Result<()> {
        let frontier = self.parent_header_frontier(header)?;
        if header.version == protocol::consensus::BLOCK_VERSION
            && header.history_root != frontier.root()
        {
            return Err(Error::Corrupt("header history root mismatch"));
        }
        let mut next = frontier;
        next.append(header)?;
        Ok(())
    }

    fn parent_header_frontier(&self, header: &BlockHeader) -> Result<HeaderFrontier> {
        if header.height == 0 && header.prev_hash == BlockHash::ZERO {
            Ok(HeaderFrontier::empty())
        } else {
            self.header_frontier(&header.prev_hash)?
                .ok_or(Error::Corrupt("parent header frontier missing"))
        }
    }

    /// Builds an inclusion path anchored to `reference.history_root`.
    /// The reference covers ancestors through its parent. Returns `None` for
    /// missing history, including opaque prefixes imported from a snapshot.
    /// The caller authenticates the reference header under normal chain rules.
    pub fn header_path(
        &self,
        reference: &BlockHash,
        height: u32,
    ) -> Result<Option<HeaderMerklePath>> {
        let Some(header) = self.header(reference)? else {
            return Ok(None);
        };
        if header.version != protocol::consensus::BLOCK_VERSION || height >= header.height {
            return Ok(None);
        }
        let Some(frontier) = self.header_frontier(&header.prev_hash)? else {
            return Ok(None);
        };
        if frontier.root() != header.history_root || frontier.count() != u64::from(header.height) {
            return Err(Error::Corrupt("reference history root mismatch"));
        }
        let read = self.db.begin_read()?;
        let nodes = read.open_table(HEADER_NODES)?;
        let Some((start, peak_level)) = mountain_for_index(height, frontier.count()) else {
            return Ok(None);
        };
        let peaks = frontier.peaks();
        let Some(mut current) = peaks
            .iter()
            .find(|(level, _)| *level == peak_level)
            .map(|(_, digest)| *digest)
        else {
            return Ok(None);
        };
        let local_index = u64::from(height).saturating_sub(start);
        let mut siblings = vec![[0; 32]; usize::try_from(peak_level).unwrap_or(0)];
        for level in (0..usize::try_from(peak_level).unwrap_or(0)).rev() {
            let Some(record) = nodes.get(&current)? else {
                return Ok(None);
            };
            let (left, right) = decode_header_node(record.value())?;
            let level = u32::try_from(level).map_err(|_| Error::Corrupt("header level"))?;
            if header_tree::header_node(level, &left, &right) != current {
                return Err(Error::Corrupt("header tree node digest mismatch"));
            }
            if (local_index >> level) & 1 == 0 {
                siblings[usize::try_from(level).unwrap_or(0)] = right;
                current = left;
            } else {
                siblings[usize::try_from(level).unwrap_or(0)] = left;
                current = right;
            }
        }
        let other_peaks = peaks
            .into_iter()
            .filter(|(level, _)| *level != peak_level)
            .collect();
        Ok(Some(HeaderMerklePath::from_parts(
            height,
            frontier.count(),
            peak_level,
            siblings,
            other_peaks,
        )?))
    }

    /// Whether a block with a well-formed, matching header is stored.
    /// This avoids decoding its body and does not certify body integrity.
    ///
    /// # Errors
    /// Returns the same read/header errors as [`Self::header`].
    pub fn contains_block(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.header(hash)?.is_some())
    }

    /// The block with the given hash.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let tx = self.db.begin_read()?;
        let blocks = tx.open_table(BLOCKS)?;
        blocks
            .get(hash.as_bytes())?
            .map(|bytes| Ok(Block::from_slice(bytes.value())?))
            .transpose()
    }

    /// Cumulative validated work for a stored block, in fixed-width big-endian form.
    /// Genesis is zero; reverted and side-chain blocks retain their index entries.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn chainwork(&self, hash: &BlockHash) -> Result<Option<[u8; 32]>> {
        let tx = self.db.begin_read()?;
        let work = tx.open_table(CHAINWORK)?;
        Ok(work.get(hash.as_bytes())?.map(|v| *v.value()))
    }

    /// The hash of the block at `height` on the current chain.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        Ok(heights
            .get(height)?
            .map(|h| BlockHash::from_bytes(*h.value())))
    }

    /// Whether `nullifier` has been spent.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn contains_nullifier(&self, nullifier: &Nullifier) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let nullifiers = tx.open_table(NULLIFIERS)?;
        Ok(nullifiers.get(&nullifier.to_bytes())?.is_some())
    }

    /// The committed nullifier-set root after `block`, if its state has been
    /// indexed. Roots remain available for stored side branches and reverted
    /// blocks so descendants can be validated against their actual parent.
    pub fn nullifier_root_at(&self, block: &BlockHash) -> Result<Option<Anchor>> {
        let tx = self.db.begin_read()?;
        let roots = tx.open_table(NULLIFIER_ROOTS)?;
        roots
            .get(block.as_bytes())?
            .map(|value| decode_nullifier_root(value.value()).map(|(root, _)| root))
            .transpose()
    }

    /// Current canonical nullifier-set root, or the empty root before genesis.
    pub fn nullifier_root(&self) -> Result<Anchor> {
        match self.tip()? {
            Some(tip) => self
                .nullifier_root_at(&tip.hash)?
                .ok_or(Error::Corrupt("tip nullifier root missing")),
            None => Ok(nullifier::empty_root(&self.chain_id()?)),
        }
    }

    /// Nullifier-set cardinality after a particular block.
    pub fn nullifier_count_at(&self, block: &BlockHash) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        let roots = tx.open_table(NULLIFIER_ROOTS)?;
        roots
            .get(block.as_bytes())?
            .map(|value| decode_nullifier_root(value.value()).map(|(_, count)| count))
            .transpose()
    }

    /// Commitment count after a particular block, including noncanonical
    /// branches retained in storage.
    pub fn commitment_count_at(&self, block: &BlockHash) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        let counts = tx.open_table(COMMITMENT_COUNTS)?;
        Ok(counts.get(block.as_bytes())?.map(|value| value.value()))
    }

    /// Commitment-tree frontier after a particular stored branch block.
    pub fn commitment_tree_at(&self, block: &BlockHash) -> Result<Option<CommitmentTree>> {
        let tx = self.db.begin_read()?;
        let frontiers = tx.open_table(BRANCH_FRONTIERS)?;
        frontiers
            .get(block.as_bytes())?
            .map(|value| Ok(CommitmentTree::from_slice(value.value())?))
            .transpose()
    }

    /// Calculate the nullifier-set transition from a specific branch parent.
    /// Duplicate nullifiers in the parent state or in `nullifiers` are rejected.
    pub fn preview_nullifier_transition(
        &self,
        parent: BlockHash,
        nullifiers: &[Nullifier],
    ) -> Result<NullifierTransition> {
        let chain_id = self.chain_id()?;
        if nullifiers.len()
            > protocol::consensus::MAX_BLOCK_TRANSACTIONS
                .saturating_mul(protocol::consensus::MAX_ACTIONS)
        {
            return Err(Error::NullifierBatchTooLarge);
        }
        let tx = self.db.begin_read()?;
        let roots = tx.open_table(NULLIFIER_ROOTS)?;
        let nodes = tx.open_table(NULLIFIER_NODES)?;
        let (parent_root, parent_count) = if parent == BlockHash::ZERO {
            (nullifier::empty_root(&chain_id), 0)
        } else {
            let bytes = roots
                .get(parent.as_bytes())?
                .ok_or(Error::Corrupt("parent nullifier root missing"))?;
            decode_nullifier_root(bytes.value())?
        };
        let Some((root, count, node_overlay)) = nullifier::transition(
            &chain_id,
            *parent_root.inner(),
            parent_count,
            nullifiers,
            |key| {
                nodes
                    .get(key)?
                    .map(|value| NodeRecord::decode(value.value()))
                    .transpose()
            },
        )?
        else {
            return Err(Error::NullifierAlreadySpent);
        };
        Ok(NullifierTransition::new(
            parent,
            nullifiers.to_vec(),
            root,
            count,
            node_overlay,
        ))
    }

    /// A circuit witness showing `nullifier` is absent from the selected
    /// branch state. `None` means the nullifier is already present.
    pub fn nullifier_non_membership_path(
        &self,
        parent: BlockHash,
        nullifier: &Nullifier,
    ) -> Result<Option<NullifierPath>> {
        let tx = self.db.begin_read()?;
        let chain_id = self.chain_id()?;
        let roots = tx.open_table(NULLIFIER_ROOTS)?;
        let nodes = tx.open_table(NULLIFIER_NODES)?;
        let root = if parent == BlockHash::ZERO {
            nullifier::empty_root(&chain_id)
        } else {
            let bytes = roots
                .get(parent.as_bytes())?
                .ok_or(Error::Corrupt("parent nullifier root missing"))?;
            decode_nullifier_root(bytes.value())?.0
        };
        nullifier::non_membership_path(&chain_id, *root.inner(), nullifier, |key| {
            nodes
                .get(key)?
                .map(|value| NodeRecord::decode(value.value()))
                .transpose()
        })
    }

    /// Export the current canonical spent-nullifier set in byte-sorted order.
    pub fn export_nullifiers(&self) -> Result<Vec<Nullifier>> {
        let tx = self.db.begin_read()?;
        let nullifiers = tx.open_table(NULLIFIERS)?;
        nullifiers
            .iter()?
            .map(|row| {
                let (key, _) = row?;
                Nullifier::from_bytes(key.value()).map_err(Error::from)
            })
            .collect()
    }

    /// Export the nullifiers whose canonical spend height is at or before
    /// `height`, in the same canonical byte order as [`Self::export_nullifiers`].
    pub fn export_nullifiers_at(&self, height: u32) -> Result<Vec<Nullifier>> {
        let tx = self.db.begin_read()?;
        let nullifiers = tx.open_table(NULLIFIERS)?;
        nullifiers
            .iter()?
            .filter_map(|row| match row {
                Ok((key, spent_height)) if spent_height.value() <= height => {
                    Some(Nullifier::from_bytes(key.value()).map_err(Error::from))
                }
                Ok(_) => None,
                Err(error) => Some(Err(Error::from(error))),
            })
            .collect()
    }

    /// Install a fully verified checkpoint snapshot atomically.
    ///
    /// The caller must have matched `checkpoint` against its configured
    /// network profile. Storage independently checks all supplied state roots,
    /// header links, sizes, and field encodings before the first database write.
    pub fn install_snapshot(
        &self,
        snapshot: &SnapshotInstall,
        mode: SnapshotInstallMode,
    ) -> Result<()> {
        self.install_snapshot_inner(snapshot, mode, None)
    }

    fn install_snapshot_inner(
        &self,
        snapshot: &SnapshotInstall,
        mode: SnapshotInstallMode,
        fail_after_stage: Option<u8>,
    ) -> Result<()> {
        let (tip_tree, node_overlay) = validate_snapshot(snapshot)?;
        let tx = self.db.begin_write()?;
        let mut replace_genesis = false;
        {
            let meta = tx.open_table(META)?;
            if meta.get("reorg_original")?.is_some() {
                return Err(Error::Corrupt("unfinished reorganization"));
            }
            let has_tip = meta.get(TIP)?.is_some();
            let recorded_chain = meta.get(CHAIN_ID)?.map(|value| *value.value());
            let recorded_rules = meta.get(RULES)?.map(|value| *value.value());
            drop(meta);
            match (mode, has_tip) {
                (SnapshotInstallMode::EmptyOnly, false) => {
                    if recorded_chain.is_some_and(|chain_id| chain_id != snapshot.chain_id)
                        || recorded_rules.is_some_and(|rules| rules != snapshot.rules_digest)
                        || !is_empty_snapshot_target(&tx)?
                    {
                        return Err(Error::SnapshotInstallMode);
                    }
                }
                (SnapshotInstallMode::EmptyOnly, true) => {
                    if recorded_chain != Some(snapshot.chain_id)
                        || recorded_rules.is_some_and(|rules| rules != snapshot.rules_digest)
                        || !is_pristine_genesis(&tx, &snapshot.chain_id)?
                    {
                        return Err(Error::SnapshotInstallMode);
                    }
                    replace_genesis = true;
                }
                (SnapshotInstallMode::ReplaceExisting, _) => {}
            }
        }
        if mode == SnapshotInstallMode::ReplaceExisting || replace_genesis {
            tx.open_table(BLOCKS)?.retain(|_, _| false)?;
            tx.open_table(HEADERS)?.retain(|_, _| false)?;
            tx.open_table(CHAINWORK)?.retain(|_, _| false)?;
            tx.open_table(HEIGHTS)?.retain(|_, _| false)?;
            tx.open_table(NULLIFIERS)?.retain(|_, _| false)?;
            tx.open_table(NULLIFIER_ROOTS)?.retain(|_, _| false)?;
            tx.open_table(NULLIFIER_NODES)?.retain(|_, _| false)?;
            tx.open_table(COMMITMENT_COUNTS)?.retain(|_, _| false)?;
            tx.open_table(BRANCH_FRONTIERS)?.retain(|_, _| false)?;
            tx.open_table(FRONTIERS)?.retain(|_, _| false)?;
            tx.open_table(HEADER_FRONTIERS)?.retain(|_, _| false)?;
            tx.open_table(HEADER_NODES)?.retain(|_, _| false)?;
            tx.open_table(TXIDS)?.retain(|_, _| false)?;
            let mut meta = tx.open_table(META)?;
            meta.retain(|key, _| key == SCHEMA)?;
        }
        maybe_inject_snapshot_fault(fail_after_stage, 0)?;

        {
            let mut meta = tx.open_table(META)?;
            meta.insert(CHAIN_ID, &snapshot.chain_id)?;
            meta.insert(RULES, &snapshot.rules_digest)?;
        }
        {
            let mut headers = tx.open_table(HEADERS)?;
            let mut heights = tx.open_table(HEIGHTS)?;
            let mut frontiers = tx.open_table(FRONTIERS)?;
            let mut commitment_counts = tx.open_table(COMMITMENT_COUNTS)?;
            for item in &snapshot.headers {
                let hash = item.header.hash();
                let header_bytes = item.header.to_vec();
                headers.insert(hash.as_bytes(), header_bytes.as_slice())?;
                heights.insert(item.header.height, hash.as_bytes())?;
                frontiers.insert(item.header.height, item.frontier.as_slice())?;
                tx.open_table(CHAINWORK)?
                    .insert(hash.as_bytes(), &item.chainwork)?;
                commitment_counts.insert(hash.as_bytes(), item.commitment_count)?;
                let nullifier_root = if item.header.height == 0 {
                    nullifier::empty_root(&snapshot.chain_id)
                } else {
                    item.header.nullifier_root
                };
                tx.open_table(NULLIFIER_ROOTS)?.insert(
                    hash.as_bytes(),
                    encode_nullifier_root(nullifier_root, item.nullifier_count).as_slice(),
                )?;
            }
        }
        {
            let mut frontier = snapshot.header_frontier.clone();
            if let Some(prefix_hash) = frontier.tip_hash() {
                persist_header_frontier_only(&tx, &prefix_hash, &frontier)?;
            }
            for item in &snapshot.headers {
                let nodes = frontier.append(&item.header)?;
                persist_header_state(&tx, &item.header, &frontier, &nodes)?;
            }
        }
        maybe_inject_snapshot_fault(fail_after_stage, 1)?;

        let tip_hash = snapshot.checkpoint.hash;
        {
            let mut nullifier_roots = tx.open_table(NULLIFIER_ROOTS)?;
            let tip_header = &snapshot
                .headers
                .last()
                .ok_or(Error::Snapshot("header suffix empty"))?
                .header;
            let installed_root = if tip_header.height == 0 {
                nullifier::empty_root(&snapshot.chain_id)
            } else {
                tip_header.nullifier_root
            };
            nullifier_roots.insert(
                tip_hash.as_bytes(),
                encode_nullifier_root(
                    installed_root,
                    u64::try_from(snapshot.nullifiers.len())
                        .map_err(|_| Error::Snapshot("nullifier count overflow"))?,
                )
                .as_slice(),
            )?;
            let mut works = tx.open_table(CHAINWORK)?;
            works.insert(tip_hash.as_bytes(), &snapshot.checkpoint.work)?;
            if works.get(&snapshot.chain_id)?.is_none() {
                works.insert(&snapshot.chain_id, &[0; 32])?;
            }
            let mut heights = tx.open_table(HEIGHTS)?;
            if heights.get(0)?.is_none() {
                heights.insert(0, &snapshot.chain_id)?;
            }
            let mut branch_frontiers = tx.open_table(BRANCH_FRONTIERS)?;
            branch_frontiers.insert(tip_hash.as_bytes(), tip_tree.to_vec().as_slice())?;
        }
        maybe_inject_snapshot_fault(fail_after_stage, 2)?;

        {
            let mut nodes = tx.open_table(NULLIFIER_NODES)?;
            for (key, record) in &node_overlay {
                nodes.insert(key, record.encode().as_slice())?;
            }
            let mut spent = tx.open_table(NULLIFIERS)?;
            for nullifier in &snapshot.nullifiers {
                spent.insert(&nullifier.to_bytes(), snapshot.checkpoint.height)?;
            }
        }
        maybe_inject_snapshot_fault(fail_after_stage, 3)?;

        {
            let mut meta = tx.open_table(META)?;
            meta.insert(TIP, tip_hash.as_bytes())?;
            meta.insert(SNAPSHOT_BASE, tip_hash.as_bytes())?;
        }
        maybe_inject_snapshot_fault(fail_after_stage, 4)?;
        tx.commit()?;
        Ok(())
    }

    /// The exact checkpoint installed as a state snapshot, if this store was
    /// bootstrapped without the corresponding full block body.
    pub fn snapshot_base(&self) -> Result<Option<BlockHash>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta
            .get(SNAPSHOT_BASE)?
            .map(|value| BlockHash::from_bytes(*value.value())))
    }

    /// Checks all transaction anchors and nullifiers against one chain
    /// snapshot. Recent frontiers are decoded once for the whole block.
    ///
    /// # Errors
    /// Fails on a database read error or corrupt tip/frontier data.
    pub fn check_block_state(
        &self,
        anchors: &[Anchor],
        spent_nullifiers: &[Nullifier],
        max_anchor_age: u32,
    ) -> Result<Option<BlockStateViolation>> {
        let read = self.db.begin_read()?;
        let meta = read.open_table(META)?;
        let Some(tip_hash) = meta.get(TIP)? else {
            return Ok(Some(BlockStateViolation::UnknownOrStaleAnchor));
        };
        let tip_hash = BlockHash::from_bytes(*tip_hash.value());
        let blocks = read.open_table(BLOCKS)?;
        let tip_height = if let Some(tip_block) = blocks.get(tip_hash.as_bytes())? {
            decode_header(tip_block.value(), &tip_hash)?.height
        } else {
            let headers = read.open_table(HEADERS)?;
            let header = headers
                .get(tip_hash.as_bytes())?
                .ok_or(Error::Corrupt("tip header missing"))?;
            decode_header(header.value(), &tip_hash)?.height
        };
        let floor = tip_height.saturating_sub(max_anchor_age);

        let frontiers = read.open_table(FRONTIERS)?;
        let mut unresolved_anchors: HashSet<_> = anchors.iter().map(Anchor::to_bytes).collect();
        for height in (floor..=tip_height).rev() {
            if unresolved_anchors.is_empty() {
                break;
            }
            if let Some(bytes) = frontiers.get(height)? {
                let frontier = CommitmentTree::from_slice(bytes.value())?;
                unresolved_anchors.remove(&frontier.root().to_bytes());
            }
        }
        if !unresolved_anchors.is_empty() {
            return Ok(Some(BlockStateViolation::UnknownOrStaleAnchor));
        }

        let nullifiers = read.open_table(NULLIFIERS)?;
        for nullifier in spent_nullifiers {
            if nullifiers.get(&nullifier.to_bytes())?.is_some() {
                return Ok(Some(BlockStateViolation::NullifierAlreadySpent));
            }
        }
        Ok(None)
    }

    /// The commitment tree after the tip, or the empty tree before genesis.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn tree(&self) -> Result<CommitmentTree> {
        match self.tip()? {
            None => Ok(CommitmentTree::empty()),
            Some(tip) => self
                .tree_at(tip.height)?
                .ok_or(Error::Corrupt("tip frontier missing")),
        }
    }

    /// The commitment tree after the block at `height`.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn tree_at(&self, height: u32) -> Result<Option<CommitmentTree>> {
        let tx = self.db.begin_read()?;
        let frontiers = tx.open_table(FRONTIERS)?;
        frontiers
            .get(height)?
            .map(|bytes| Ok(CommitmentTree::from_slice(bytes.value())?))
            .transpose()
    }

    /// Whether an anchor equals the tree root at some height on the chain.
    ///
    /// Scans back from the tip up to `max_depth` blocks; anchors older than
    /// that are refused so transactions cannot spend against ancient roots.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn anchor_height(
        &self,
        anchor: &protocol::transaction::Anchor,
        max_depth: u32,
    ) -> Result<Option<u32>> {
        let Some(tip) = self.tip()? else {
            return Ok(None);
        };
        let floor = tip.height.saturating_sub(max_depth);
        for height in (floor..=tip.height).rev() {
            if self.tree_at(height)?.is_some_and(|t| t.root() == *anchor) {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Deletes frontiers of heights below `height`, which limits how far
    /// back a revert can go. The caller keeps enough for its reorg policy.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn prune_frontiers_below(&self, height: u32) -> Result<()> {
        let tx = self.db.begin_write()?;
        let meta = tx.open_table(META)?;
        if meta.get("reorg_original")?.is_some() {
            return Ok(());
        }
        let snapshot_base = meta
            .get(SNAPSHOT_BASE)?
            .map(|value| BlockHash::from_bytes(*value.value()));
        drop(meta);
        let snapshot_base_height = if let Some(hash) = snapshot_base {
            let headers = tx.open_table(HEADERS)?;
            let result = headers
                .get(hash.as_bytes())?
                .map(|value| decode_header(value.value(), &hash).map(|header| header.height))
                .transpose()?;
            result
        } else {
            None
        };
        {
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.retain(|h, _| h >= height || Some(h) == snapshot_base_height)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Prune state for side branches that can no longer be reorganized to,
    /// then mark-and-sweep sparse-tree nodes reachable from retained roots.
    ///
    /// `max_reorg_depth` is the fork-choice floor. `frontier_floor` is the
    /// caller-computed lower height needed for anchor and DAA history.
    pub fn prune_branch_state(
        &self,
        max_reorg_depth: u32,
        frontier_floor: u32,
        pinned_ranges: &[(u32, u32)],
    ) -> Result<()> {
        let tx = self.db.begin_write()?;
        let meta = tx.open_table(META)?;
        let reorg_pending = meta.get("reorg_original")?.is_some();
        if reorg_pending {
            return Ok(());
        }
        let tip_hash = meta
            .get(TIP)?
            .map(|value| BlockHash::from_bytes(*value.value()));
        let Some(tip_hash) = tip_hash else {
            return Ok(());
        };
        let snapshot_base = meta
            .get(SNAPSHOT_BASE)?
            .map(|value| BlockHash::from_bytes(*value.value()));
        let chain_id = meta.get(CHAIN_ID)?.map_or([0; 32], |value| *value.value());
        drop(meta);
        let tip_header = {
            let blocks = tx.open_table(BLOCKS)?;
            let bytes = blocks
                .get(tip_hash.as_bytes())?
                .map(|bytes| bytes.value().to_vec());
            drop(blocks);
            if let Some(bytes) = bytes {
                decode_header(&bytes, &tip_hash)?
            } else {
                let headers = tx.open_table(HEADERS)?;
                let result = headers.get(tip_hash.as_bytes())?;
                let header = result
                    .map(|bytes| decode_header(bytes.value(), &tip_hash))
                    .transpose()?
                    .ok_or(Error::Corrupt("tip header missing"))?;
                header
            }
        };
        let configured_floor = tip_header.height.saturating_sub(max_reorg_depth);
        let height_table = tx.open_table(HEIGHTS)?;
        let mut canonical = HashMap::<u32, BlockHash>::new();
        for row in height_table.iter()? {
            let (height, hash) = row?;
            canonical.insert(height.value(), BlockHash::from_bytes(*hash.value()));
        }
        drop(height_table);
        let headers_table = tx.open_table(HEADERS)?;
        let mut all_headers = HashMap::<BlockHash, BlockHeader>::new();
        for row in headers_table.iter()? {
            let (hash, bytes) = row?;
            let key = BlockHash::from_bytes(*hash.value());
            all_headers.insert(key, decode_header(bytes.value(), &key)?);
        }
        drop(headers_table);
        let fork_floor = snapshot_base
            .and_then(|hash| all_headers.get(&hash).map(|header| header.height))
            .map_or(configured_floor, |height| configured_floor.max(height));
        let mut eligible_side = HashSet::<BlockHash>::new();
        for (hash, header) in &all_headers {
            if canonical.get(&header.height) == Some(hash) {
                continue;
            }
            let mut cursor = header;
            loop {
                let parent_hash = cursor.prev_hash;
                let Some(parent) = all_headers.get(&parent_hash) else {
                    break;
                };
                if parent.height >= cursor.height {
                    return Err(Error::Corrupt("branch header heights do not decrease"));
                }
                if canonical.get(&parent.height) == Some(&parent_hash) {
                    if parent.height >= fork_floor {
                        eligible_side.insert(*hash);
                    }
                    break;
                }
                if parent.height < fork_floor {
                    break;
                }
                cursor = parent;
            }
        }
        let retention_floor = fork_floor;
        let retained_state: HashSet<BlockHash> = all_headers
            .iter()
            .filter_map(|(hash, header)| {
                (canonical.get(&header.height) == Some(hash) && header.height >= retention_floor
                    || canonical.get(&header.height) == Some(hash)
                        && pinned_ranges
                            .iter()
                            .any(|(floor, ceiling)| (*floor..=*ceiling).contains(&header.height))
                    || eligible_side.contains(hash))
                .then_some(*hash)
            })
            .collect();
        let mut retained_roots = Vec::new();
        {
            let roots = tx.open_table(NULLIFIER_ROOTS)?;
            for hash in &retained_state {
                if let Some(value) = roots.get(hash.as_bytes())? {
                    retained_roots.push(decode_nullifier_root(value.value())?.0);
                }
            }
        }
        let nodes = tx.open_table(NULLIFIER_NODES)?;
        let marked = nullifier::reachable_nodes(&chain_id, &retained_roots, |key| {
            nodes
                .get(key)?
                .map(|value| NodeRecord::decode(value.value()))
                .transpose()
        })?;
        drop(nodes);
        {
            tx.open_table(FRONTIERS)?.retain(|height, _| {
                height >= frontier_floor
                    || pinned_ranges
                        .iter()
                        .any(|(floor, ceiling)| (*floor..=*ceiling).contains(&height))
                    || snapshot_base
                        .and_then(|hash| all_headers.get(&hash).map(|header| header.height))
                        == Some(height)
            })?;
            tx.open_table(BRANCH_FRONTIERS)?.retain(|hash, _| {
                let block_hash = BlockHash::from_bytes(*hash);
                retained_state.contains(&block_hash)
            })?;
            tx.open_table(COMMITMENT_COUNTS)?.retain(|hash, _| {
                let block_hash = BlockHash::from_bytes(*hash);
                retained_state.contains(&block_hash)
            })?;
            tx.open_table(NULLIFIER_ROOTS)?.retain(|hash, _| {
                let block_hash = BlockHash::from_bytes(*hash);
                retained_state.contains(&block_hash)
            })?;
            tx.open_table(NULLIFIER_NODES)?
                .retain(|hash, _| marked.contains(hash))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores a block's bytes without applying it, for side-chain blocks
    /// that may become the best chain later, atomically with its validated work.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn put_block(&self, block: &Block, chainwork: &[u8; 32]) -> Result<()> {
        block.check_body_root()?;
        let header_history =
            if block.header().height == 0 && block.header().prev_hash == BlockHash::ZERO {
                let mut frontier = HeaderFrontier::empty();
                let nodes = frontier.append(block.header())?;
                Some((frontier, nodes))
            } else if let Some(mut frontier) = self.header_frontier(&block.header().prev_hash)? {
                if block.header().version == protocol::consensus::BLOCK_VERSION
                    && block.header().history_root != frontier.root()
                {
                    return Err(Error::Corrupt("header history root mismatch"));
                }
                let nodes = frontier.append(block.header())?;
                Some((frontier, nodes))
            } else {
                // This low-level path is also used to retain orphan/raw blocks.
                // Such a block has no authenticated branch frontier yet.
                None
            };
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(block.hash().as_bytes(), block.to_vec().as_slice())?;
            tx.open_table(HEADERS)?
                .insert(block.hash().as_bytes(), block.header().to_vec().as_slice())?;
            tx.open_table(CHAINWORK)?
                .insert(block.hash().as_bytes(), chainwork)?;
            if let Some((frontier, nodes)) = &header_history {
                persist_header_state(&tx, block.header(), frontier, nodes)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Store a validated side-branch block together with its branch-specific
    /// nullifier root and commitment frontier. All indexes become visible in
    /// one redb transaction.
    pub fn put_block_with_nullifier_transition(
        &self,
        block: &Block,
        tree: &CommitmentTree,
        chainwork: &[u8; 32],
        transition: &NullifierTransition,
    ) -> Result<()> {
        validate_transition_for_block(block, transition)?;
        let parent_tree = if block.header().prev_hash == BlockHash::ZERO {
            CommitmentTree::empty()
        } else {
            self.commitment_tree_at(&block.header().prev_hash)?
                .ok_or(Error::Corrupt("parent commitment frontier missing"))?
        };
        let mut expected_tree = parent_tree;
        for tx in block.transactions() {
            for action in tx.actions() {
                expected_tree.append(action.body().cmx())?;
            }
        }
        if expected_tree != *tree || tree.root() != block.header().commitment_root {
            return Err(Error::Corrupt("side-branch commitment frontier mismatch"));
        }
        let parent_count = if block.header().prev_hash == BlockHash::ZERO {
            0
        } else {
            self.commitment_count_at(&block.header().prev_hash)?
                .ok_or(Error::Corrupt("parent commitment count missing"))?
        };
        let new_commitments = block.transactions().iter().try_fold(0u64, |sum, tx| {
            sum.checked_add(
                u64::try_from(tx.actions().len())
                    .map_err(|_| Error::Corrupt("commitment count"))?,
            )
            .ok_or(Error::Corrupt("commitment count overflow"))
        })?;
        if parent_count.checked_add(new_commitments) != Some(tree.size()) {
            return Err(Error::Corrupt("side-branch commitment count mismatch"));
        }

        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(block.hash().as_bytes(), block.to_vec().as_slice())?;
            tx.open_table(HEADERS)?
                .insert(block.hash().as_bytes(), block.header().to_vec().as_slice())?;
            tx.open_table(CHAINWORK)?
                .insert(block.hash().as_bytes(), chainwork)?;
            persist_branch_state(&tx, block, tree, transition)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Appends `block` to the tip, spending its nullifiers and recording
    /// `tree`, the commitment tree after the block. All or nothing.
    ///
    /// The caller has validated the block and computed cumulative work from
    /// its validated target and indexed parent; this only checks that it
    /// extends the tip.
    ///
    /// # Errors
    /// Returns [`Error::NotOnTip`] if the block's previous hash or height
    /// does not match the tip, or a write error.
    pub fn apply(&self, block: &Block, tree: &CommitmentTree, chainwork: &[u8; 32]) -> Result<()> {
        let transition =
            self.preview_nullifier_transition(block.header().prev_hash, &block_nullifiers(block))?;
        self.apply_with_nullifier_transition(block, tree, chainwork, &transition)
    }

    /// Apply a block with a transition already computed from its parent root.
    /// This avoids recomputing the sparse-tree paths after circuit proving.
    pub fn apply_with_nullifier_transition(
        &self,
        block: &Block,
        tree: &CommitmentTree,
        chainwork: &[u8; 32],
        transition: &NullifierTransition,
    ) -> Result<()> {
        let header = block.header();
        let expected_prev = match self.tip()? {
            Some(t) => (t.hash, next_height(t.height)?),
            None => (BlockHash::ZERO, 0),
        };
        if (header.prev_hash, header.height) != expected_prev {
            return Err(Error::NotOnTip);
        }
        validate_transition_for_block(block, transition)?;
        let hash = block.hash();
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(hash.as_bytes(), block.to_vec().as_slice())?;
            tx.open_table(HEADERS)?
                .insert(hash.as_bytes(), header.to_vec().as_slice())?;
            tx.open_table(CHAINWORK)?
                .insert(hash.as_bytes(), chainwork)?;
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.insert(header.height, hash.as_bytes())?;
            let mut nullifiers = tx.open_table(NULLIFIERS)?;
            for nf in block
                .transactions()
                .iter()
                .flat_map(protocol::transaction::Transaction::nullifiers)
            {
                if nullifiers.insert(&nf.to_bytes(), header.height)?.is_some() {
                    return Err(Error::Corrupt("nullifier already spent"));
                }
            }
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.insert(header.height, tree.to_vec().as_slice())?;
            let mut txids = tx.open_table(TXIDS)?;
            for (index, transaction) in block.transactions().iter().enumerate() {
                let index = u32::try_from(index).map_err(|_| Error::Corrupt("index"))?;
                txids.insert(
                    transaction.txid().as_bytes(),
                    &encode_location(header.height, index),
                )?;
            }
            let mut meta = tx.open_table(META)?;
            meta.insert(TIP, hash.as_bytes())?;
        }
        persist_branch_state(&tx, block, tree, transition)?;
        tx.commit()?;
        Ok(())
    }

    /// Removes the tip block, unspending its nullifiers. The block bytes
    /// stay in the block table so a reorg can be inspected.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] before genesis, or a write error.
    pub fn revert(&self) -> Result<Block> {
        let tip = self.tip()?.ok_or(Error::Corrupt("nothing to revert"))?;
        if self.snapshot_base()? == Some(tip.hash) {
            return Err(Error::Corrupt("cannot revert below snapshot base"));
        }
        let block = self
            .block(&tip.hash)?
            .ok_or(Error::Corrupt("tip block missing"))?;
        let tx = self.db.begin_write()?;
        {
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.remove(tip.height)?;
            let mut nullifiers = tx.open_table(NULLIFIERS)?;
            for nf in block
                .transactions()
                .iter()
                .flat_map(protocol::transaction::Transaction::nullifiers)
            {
                nullifiers.remove(&nf.to_bytes())?;
            }
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.remove(tip.height)?;
            let mut txids = tx.open_table(TXIDS)?;
            for transaction in block.transactions() {
                txids.remove(transaction.txid().as_bytes())?;
            }
            let mut meta = tx.open_table(META)?;
            if tip.height == 0 {
                meta.remove(TIP)?;
            } else {
                meta.insert(TIP, block.header().prev_hash.as_bytes())?;
            }
        }
        tx.commit()?;
        Ok(block)
    }
}

fn decode_header_node(bytes: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if bytes.len() != 64 {
        return Err(Error::Corrupt("header tree node length"));
    }
    let mut left = [0; 32];
    let mut right = [0; 32];
    left.copy_from_slice(&bytes[..32]);
    right.copy_from_slice(&bytes[32..]);
    Ok((left, right))
}

fn persist_header_state(
    tx: &redb::WriteTransaction,
    header: &BlockHeader,
    frontier: &HeaderFrontier,
    records: &[([u8; 32], [u8; 32], [u8; 32])],
) -> Result<()> {
    {
        let mut nodes = tx.open_table(HEADER_NODES)?;
        for (digest, left, right) in records {
            let mut encoded = [0; 64];
            encoded[..32].copy_from_slice(left);
            encoded[32..].copy_from_slice(right);
            let existing = nodes.get(digest)?.map(|value| value.value().to_vec());
            if let Some(existing) = existing {
                if existing != encoded {
                    return Err(Error::Corrupt("header tree node content collision"));
                }
            } else {
                nodes.insert(digest, encoded.as_slice())?;
            }
        }
    }
    persist_header_frontier_only(tx, &header.hash(), frontier)
}

fn persist_header_frontier_only(
    tx: &redb::WriteTransaction,
    hash: &BlockHash,
    frontier: &HeaderFrontier,
) -> Result<()> {
    let encoded = frontier.to_vec();
    let mut frontiers = tx.open_table(HEADER_FRONTIERS)?;
    let existing = frontiers
        .get(hash.as_bytes())?
        .map(|value| value.value().to_vec());
    if let Some(existing) = existing {
        if existing != encoded {
            return Err(Error::Corrupt("block header frontier changed"));
        }
    } else {
        frontiers.insert(hash.as_bytes(), encoded.as_slice())?;
    }
    Ok(())
}

fn encode_location(height: u32, index: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&height.to_le_bytes());
    out[4..].copy_from_slice(&index.to_le_bytes());
    out
}

fn decode_location(bytes: [u8; 8]) -> (u32, u32) {
    let (height, index) = bytes.split_at(4);
    (
        u32::from_le_bytes(height.try_into().unwrap_or([0; 4])),
        u32::from_le_bytes(index.try_into().unwrap_or([0; 4])),
    )
}

fn encode_nullifier_root(root: Anchor, count: u64) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(&root.to_bytes());
    out[32..].copy_from_slice(&count.to_le_bytes());
    out
}

fn decode_nullifier_root(bytes: &[u8]) -> Result<(Anchor, u64)> {
    if bytes.len() != 40 {
        return Err(Error::Corrupt("nullifier root record length"));
    }
    let mut root_bytes = [0u8; 32];
    let mut count_bytes = [0u8; 8];
    root_bytes.copy_from_slice(&bytes[..32]);
    count_bytes.copy_from_slice(&bytes[32..]);
    Ok((
        Anchor::from_base(base_from_bytes(&root_bytes)?),
        u64::from_le_bytes(count_bytes),
    ))
}

fn block_nullifiers(block: &Block) -> Vec<Nullifier> {
    block
        .transactions()
        .iter()
        .flat_map(Transaction::nullifiers)
        .copied()
        .collect()
}

fn validate_transition_for_block(block: &Block, transition: &NullifierTransition) -> Result<()> {
    if transition.parent() != block.header().prev_hash
        || transition.nullifiers() != block_nullifiers(block).as_slice()
    {
        return Err(Error::Corrupt("nullifier transition does not match block"));
    }
    Ok(())
}

fn persist_branch_state(
    tx: &redb::WriteTransaction,
    block: &Block,
    tree: &CommitmentTree,
    transition: &NullifierTransition,
) -> Result<()> {
    validate_transition_for_block(block, transition)?;
    block.check_body_root()?;
    let mut header_frontier =
        if block.header().height == 0 && block.header().prev_hash == BlockHash::ZERO {
            HeaderFrontier::empty()
        } else {
            let frontiers = tx.open_table(HEADER_FRONTIERS)?;
            let encoded = frontiers
                .get(block.header().prev_hash.as_bytes())?
                .ok_or(Error::Corrupt("parent header frontier missing"))?;
            HeaderFrontier::from_slice(encoded.value())?
        };
    if block.header().version == protocol::consensus::BLOCK_VERSION
        && block.header().history_root != header_frontier.root()
    {
        return Err(Error::Corrupt("header history root mismatch"));
    }
    let header_nodes = header_frontier.append(block.header())?;
    persist_header_state(tx, block.header(), &header_frontier, &header_nodes)?;
    {
        let mut nodes = tx.open_table(NULLIFIER_NODES)?;
        for (key, record) in transition.nodes() {
            let encoded = record.encode();
            let existing = nodes.get(key)?.map(|value| value.value().to_vec());
            if let Some(existing) = existing {
                if existing.as_slice() != encoded.as_slice() {
                    return Err(Error::Corrupt("nullifier tree node content collision"));
                }
            } else {
                nodes.insert(key, encoded.as_slice())?;
            }
        }
    }
    let root_record = encode_nullifier_root(transition.root(), transition.count());
    {
        let mut roots = tx.open_table(NULLIFIER_ROOTS)?;
        let existing = roots
            .get(block.hash().as_bytes())?
            .map(|value| value.value().to_vec());
        if let Some(existing) = existing {
            if existing.as_slice() != root_record.as_slice() {
                return Err(Error::Corrupt("block nullifier root changed"));
            }
        } else {
            roots.insert(block.hash().as_bytes(), root_record.as_slice())?;
        }
    }
    {
        let mut counts = tx.open_table(COMMITMENT_COUNTS)?;
        let existing = counts
            .get(block.hash().as_bytes())?
            .map(|value| value.value());
        if let Some(existing) = existing {
            if existing != tree.size() {
                return Err(Error::Corrupt("block commitment count changed"));
            }
        } else {
            counts.insert(block.hash().as_bytes(), tree.size())?;
        }
    }
    {
        let mut frontiers = tx.open_table(BRANCH_FRONTIERS)?;
        let encoded = tree.to_vec();
        let existing = frontiers
            .get(block.hash().as_bytes())?
            .map(|value| value.value().to_vec());
        if let Some(existing) = existing {
            if existing.as_slice() != encoded.as_slice() {
                return Err(Error::Corrupt("block commitment frontier changed"));
            }
        } else {
            frontiers.insert(block.hash().as_bytes(), encoded.as_slice())?;
        }
    }
    Ok(())
}

fn maybe_inject_snapshot_fault(fail_after_stage: Option<u8>, stage: u8) -> Result<()> {
    if fail_after_stage == Some(stage) {
        return Err(Error::Snapshot("injected install fault"));
    }
    Ok(())
}

fn is_pristine_genesis(tx: &redb::WriteTransaction, chain_id: &[u8; 32]) -> Result<bool> {
    let blocks = tx.open_table(BLOCKS)?;
    let headers = tx.open_table(HEADERS)?;
    let heights = tx.open_table(HEIGHTS)?;
    let nullifiers = tx.open_table(NULLIFIERS)?;
    if blocks.len()? != 1
        || headers.len()? != 1
        || heights.len()? != 1
        || !nullifiers.is_empty()?
        || !tx.open_table(NULLIFIER_NODES)?.is_empty()?
        || tx.open_table(NULLIFIER_ROOTS)?.len()? != 1
        || tx.open_table(BRANCH_FRONTIERS)?.len()? != 1
        || tx.open_table(COMMITMENT_COUNTS)?.len()? != 1
        || tx.open_table(FRONTIERS)?.len()? != 1
        || tx.open_table(HEADER_FRONTIERS)?.len()? != 1
        || !tx.open_table(HEADER_NODES)?.is_empty()?
        || !tx.open_table(TXIDS)?.is_empty()?
        || tx.open_table(CHAINWORK)?.len()? != 1
    {
        return Ok(false);
    }
    let Some(hash) = heights.get(0)? else {
        return Ok(false);
    };
    let hash = BlockHash::from_bytes(*hash.value());
    let Some(bytes) = blocks.get(hash.as_bytes())? else {
        return Ok(false);
    };
    let block = Block::from_slice(bytes.value())?;
    let Some(header_bytes) = headers.get(hash.as_bytes())? else {
        return Ok(false);
    };
    let header = decode_header(header_bytes.value(), &hash)?;
    if header != *block.header() {
        return Ok(false);
    }
    Ok(block.header().height == 0
        && block.transactions().is_empty()
        && block.hash().as_bytes() == chain_id
        && tx
            .open_table(CHAINWORK)?
            .get(chain_id)?
            .is_some_and(|v| *v.value() == [0; 32]))
}

fn is_empty_snapshot_target(tx: &redb::WriteTransaction) -> Result<bool> {
    if !tx.open_table(BLOCKS)?.is_empty()?
        || !tx.open_table(HEADERS)?.is_empty()?
        || !tx.open_table(CHAINWORK)?.is_empty()?
        || !tx.open_table(HEIGHTS)?.is_empty()?
        || !tx.open_table(NULLIFIERS)?.is_empty()?
        || !tx.open_table(NULLIFIER_ROOTS)?.is_empty()?
        || !tx.open_table(NULLIFIER_NODES)?.is_empty()?
        || !tx.open_table(COMMITMENT_COUNTS)?.is_empty()?
        || !tx.open_table(BRANCH_FRONTIERS)?.is_empty()?
        || !tx.open_table(HEADER_FRONTIERS)?.is_empty()?
        || !tx.open_table(HEADER_NODES)?.is_empty()?
        || !tx.open_table(FRONTIERS)?.is_empty()?
        || !tx.open_table(TXIDS)?.is_empty()?
    {
        return Ok(false);
    }
    let meta = tx.open_table(META)?;
    for row in meta.iter()? {
        let (key, _) = row?;
        if ![SCHEMA, CHAIN_ID, RULES].contains(&key.value()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_snapshot(
    snapshot: &SnapshotInstall,
) -> Result<(CommitmentTree, Vec<(Encoded, NodeRecord)>)> {
    if snapshot.headers.is_empty() {
        return Err(Error::Snapshot("header suffix empty"));
    }
    if snapshot
        .nullifiers
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::Snapshot("nullifiers not in strict canonical order"));
    }
    let (nullifier_root, nullifier_count, node_overlay) =
        nullifier::build_set(&snapshot.chain_id, &snapshot.nullifiers)?;
    let expected_count = u64::try_from(snapshot.nullifiers.len())
        .map_err(|_| Error::Snapshot("nullifier count overflow"))?;
    if nullifier_count != expected_count {
        return Err(Error::Snapshot("nullifier count mismatch"));
    }

    let mut previous: Option<&SnapshotHeader> = None;
    let mut header_frontier = snapshot.header_frontier.clone();
    let mut tip_tree = None;
    for item in &snapshot.headers {
        let header = &item.header;
        if header.version == protocol::consensus::BLOCK_VERSION
            && header.history_root != header_frontier.root()
        {
            return Err(Error::Snapshot("header history root mismatch"));
        }
        header_frontier.append(header)?;
        let hash = header.hash();
        if let Some(parent) = previous {
            if header.height != parent.header.height.saturating_add(1)
                || header.prev_hash != parent.header.hash()
                || item.commitment_count < parent.commitment_count
                || item.nullifier_count < parent.nullifier_count
            {
                return Err(Error::Snapshot("header suffix is not contiguous"));
            }
            // Chain-level checkpoint verification validates cumulative work.
            // Storage has no dependency on the consensus target/work module.
        }
        let tree = CommitmentTree::from_slice(&item.frontier)?;
        if tree.root() != header.commitment_root || tree.size() != item.commitment_count {
            return Err(Error::Snapshot("commitment frontier root/count mismatch"));
        }
        if header.version == protocol::consensus::BLOCK_VERSION && header.height > 0 {
            let expected_state = protocol::state::state_root(
                &snapshot.chain_id,
                header.height,
                tree.root(),
                tree.size(),
                header.nullifier_root,
                item.nullifier_count,
            );
            if expected_state != header.state_root {
                return Err(Error::Snapshot("header state root mismatch"));
            }
        } else if header.version != protocol::consensus::BLOCK_VERSION
            || header.height != 0
            || header.prev_hash != BlockHash::ZERO
            || header.hash().as_bytes() != &snapshot.chain_id
            || header.nullifier_root != Anchor::from_base(crypto::pallas::Base::from(0u64))
            || header.state_root != Anchor::from_base(crypto::pallas::Base::from(0u64))
            || item.commitment_count != 0
            || item.nullifier_count != 0
        {
            return Err(Error::Snapshot("invalid header version/height"));
        }
        if hash == snapshot.checkpoint.hash {
            if header.height != snapshot.checkpoint.height
                || header.state_root != snapshot.checkpoint.state_root
                || (header.height > 0 && header.nullifier_root != nullifier_root)
                || item.nullifier_count != nullifier_count
            {
                return Err(Error::Snapshot("checkpoint header/state mismatch"));
            }
            tip_tree = Some(tree);
        }
        previous = Some(item);
    }
    let tip_entry = snapshot
        .headers
        .last()
        .ok_or(Error::Snapshot("header suffix empty"))?;
    if tip_entry.header.hash() != snapshot.checkpoint.hash
        || tip_entry.header.height != snapshot.checkpoint.height
        || tip_entry.header.state_root != snapshot.checkpoint.state_root
        || tip_entry.chainwork != snapshot.checkpoint.work
        || tip_tree.is_none()
    {
        return Err(Error::Snapshot("checkpoint is not suffix tip"));
    }
    Ok((
        tip_tree.ok_or(Error::Snapshot("checkpoint frontier missing"))?,
        node_overlay,
    ))
}

#[cfg(test)]
fn install_snapshot_fault_for_test(
    store: &Store,
    snapshot: &SnapshotInstall,
    mode: SnapshotInstallMode,
    stage: u8,
) -> Result<()> {
    store.install_snapshot_inner(snapshot, mode, Some(stage))
}

/// Decode only the fixed-size header while checking its storage-key identity.
fn decode_header(bytes: &[u8], hash: &BlockHash) -> Result<BlockHeader> {
    let version = *bytes
        .first()
        .ok_or(Error::Corrupt("truncated block header"))?;
    let length = header_len_for_version(version).ok_or(Error::Corrupt("unknown block version"))?;
    let prefix = bytes
        .get(..length)
        .ok_or(Error::Corrupt("truncated block header"))?;
    let header = BlockHeader::from_slice(prefix)?;
    if header.hash() != *hash {
        return Err(Error::Corrupt("block header hash mismatch"));
    }
    Ok(header)
}

fn schema_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    // The new namespace distinguishes this layout from pre-release stores
    // that also used numeric schema version 1.
    const SCHEMA_DOMAIN: &[u8] = b"KRYPTOS:STORE:V1-MERKLE:";
    out[..SCHEMA_DOMAIN.len()].copy_from_slice(SCHEMA_DOMAIN);
    out[SCHEMA_DOMAIN.len()..][..4].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use crypto::pallas;
    use protocol::block::{empty_header, BlockHeader};
    use protocol::transaction::Anchor;

    use super::*;

    #[test]
    fn locations_round_trip() {
        assert_eq!(decode_location(encode_location(7, 3)), (7, 3));
        assert_eq!(decode_location(encode_location(u32::MAX, 0)), (u32::MAX, 0));
    }

    fn snapshot_fixture() -> (SnapshotInstall, Block) {
        let empty = CommitmentTree::empty();
        let mut genesis_header = empty_header(0, BlockHash::ZERO, empty.root());
        genesis_header.timestamp = 1;
        let genesis = Block::new(genesis_header, Vec::new());
        let chain_id = *genesis.hash().as_bytes();
        let mut header_frontier = HeaderFrontier::empty();
        header_frontier.append(genesis.header()).unwrap();
        let nullifier = Nullifier::from_base(&pallas::Base::from(7));
        let nullifiers = vec![nullifier];
        let nf_root = nullifier::root_from_set(&chain_id, &nullifiers).unwrap();
        let mut tip_header = empty_header(1, genesis.hash(), empty.root());
        tip_header.timestamp = 2;
        tip_header.body_root = protocol::body_tree::body_root(&[]).unwrap();
        tip_header.history_root = header_frontier.root();
        tip_header.nullifier_root = nf_root;
        tip_header.state_root =
            protocol::state::state_root(&chain_id, 1, empty.root(), 0, nf_root, 1);
        let checkpoint = SnapshotCheckpoint {
            height: 1,
            hash: tip_header.hash(),
            work: [4; 32],
            state_root: tip_header.state_root,
        };
        let snapshot = SnapshotInstall {
            chain_id,
            rules_digest: [8; 32],
            checkpoint,
            header_frontier: HeaderFrontier::empty(),
            headers: vec![
                SnapshotHeader {
                    header: genesis.header().clone(),
                    commitment_count: 0,
                    nullifier_count: 0,
                    chainwork: [0; 32],
                    frontier: empty.to_vec(),
                },
                SnapshotHeader {
                    header: tip_header,
                    commitment_count: 0,
                    nullifier_count: 1,
                    chainwork: [4; 32],
                    frontier: empty.to_vec(),
                },
            ],
            nullifiers,
        };
        (snapshot, genesis)
    }

    #[test]
    fn checkpoint_snapshot_installs_into_empty_store_and_serves_tip_header() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("snapshot.redb")).unwrap();
        let (snapshot, _) = snapshot_fixture();
        store
            .install_snapshot(&snapshot, SnapshotInstallMode::EmptyOnly)
            .unwrap();
        let tip = store.tip().unwrap().unwrap();
        assert_eq!(tip.height, snapshot.checkpoint.height);
        assert_eq!(tip.hash, snapshot.checkpoint.hash);
        assert_eq!(
            store.header(&tip.hash).unwrap().unwrap(),
            snapshot.headers[1].header
        );
        assert!(store.block(&tip.hash).unwrap().is_none());
        assert_eq!(store.snapshot_base().unwrap(), Some(tip.hash));
        assert_eq!(store.chain_id().unwrap(), snapshot.chain_id);
        assert_eq!(store.rules_digest().unwrap(), Some(snapshot.rules_digest));
        assert_eq!(
            store.chainwork(&tip.hash).unwrap(),
            Some(snapshot.checkpoint.work)
        );
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(
            store.nullifier_root().unwrap(),
            snapshot.headers[1].header.nullifier_root
        );
        assert!(store.contains_nullifier(&snapshot.nullifiers[0]).unwrap());
        assert!(matches!(
            store.install_snapshot(&snapshot, SnapshotInstallMode::EmptyOnly),
            Err(Error::SnapshotInstallMode)
        ));
    }

    #[test]
    fn empty_only_snapshot_mode_never_replaces_a_running_chain() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("running.redb")).unwrap();
        let (snapshot, genesis) = snapshot_fixture();
        store.set_chain_id(&snapshot.chain_id).unwrap();
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        store.set_rules_digest(&snapshot.rules_digest).unwrap();
        let mut header = empty_header(1, genesis.hash(), CommitmentTree::empty().root());
        bind_header_history(&store, &mut header);
        header.nullifier_root = nullifier::empty_root(&snapshot.chain_id);
        header.state_root = protocol::state::state_root(
            &snapshot.chain_id,
            1,
            header.commitment_root,
            0,
            header.nullifier_root,
            0,
        );
        let block = Block::new(header, Vec::new());
        store
            .apply(&block, &CommitmentTree::empty(), &[1; 32])
            .unwrap();
        assert!(matches!(
            store.install_snapshot(&snapshot, SnapshotInstallMode::EmptyOnly),
            Err(Error::SnapshotInstallMode)
        ));
        assert_eq!(store.tip().unwrap().unwrap().hash, block.hash());
        assert_eq!(store.block(&block.hash()).unwrap(), Some(block));
        assert!(store.snapshot_base().unwrap().is_none());
    }

    #[test]
    fn snapshot_install_faults_leave_empty_store_unchanged_at_every_stage() {
        for stage in 0..=4 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("fault.redb");
            let store = Store::open(&path).unwrap();
            let (snapshot, _) = snapshot_fixture();
            assert!(install_snapshot_fault_for_test(
                &store,
                &snapshot,
                SnapshotInstallMode::EmptyOnly,
                stage,
            )
            .is_err());
            drop(store);
            let store = Store::open(&path).unwrap();
            assert_eq!(store.tip().unwrap(), None);
            assert_eq!(store.chain_id().unwrap(), [0; 32]);
            assert_eq!(store.rules_digest().unwrap(), None);
            assert!(store.export_nullifiers().unwrap().is_empty());
            assert!(store.header(&snapshot.checkpoint.hash).unwrap().is_none());
        }
    }

    #[test]
    fn snapshot_install_faults_preserve_genesis_only_store() {
        for stage in 0..=4 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("genesis.redb");
            let store = Store::open(&path).unwrap();
            let (snapshot, genesis) = snapshot_fixture();
            store.set_chain_id(&snapshot.chain_id).unwrap();
            store
                .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
                .unwrap();
            store.set_rules_digest(&snapshot.rules_digest).unwrap();
            assert!(install_snapshot_fault_for_test(
                &store,
                &snapshot,
                SnapshotInstallMode::EmptyOnly,
                stage,
            )
            .is_err());
            drop(store);
            let store = Store::open(&path).unwrap();
            assert_eq!(store.tip().unwrap().unwrap().hash, genesis.hash());
            assert_eq!(store.block(&genesis.hash()).unwrap(), Some(genesis.clone()));
            assert_eq!(store.chain_id().unwrap(), snapshot.chain_id);
            assert_eq!(store.rules_digest().unwrap(), Some(snapshot.rules_digest));
            assert_eq!(
                store.nullifier_root_at(&genesis.hash()).unwrap(),
                Some(nullifier::empty_root(&snapshot.chain_id))
            );
        }
    }

    #[test]
    fn explicit_replace_mode_is_atomic_when_install_fails() {
        for stage in 0..=4 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("replace.redb");
            let store = Store::open(&path).unwrap();
            let (snapshot, genesis) = snapshot_fixture();
            store.set_chain_id(&snapshot.chain_id).unwrap();
            store
                .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
                .unwrap();
            store.set_rules_digest(&snapshot.rules_digest).unwrap();
            assert!(install_snapshot_fault_for_test(
                &store,
                &snapshot,
                SnapshotInstallMode::ReplaceExisting,
                stage,
            )
            .is_err());
            drop(store);
            let store = Store::open(&path).unwrap();
            assert_eq!(store.tip().unwrap().unwrap().hash, genesis.hash());
            assert_eq!(store.block(&genesis.hash()).unwrap(), Some(genesis.clone()));
            assert_eq!(store.hash_at(1).unwrap(), None);
            assert!(store.snapshot_base().unwrap().is_none());
        }
    }

    #[test]
    fn branch_gc_prunes_old_frontiers_and_sweeps_only_unreachable_sparse_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("gc.redb")).unwrap();
        let (snapshot, _) = snapshot_fixture();
        store
            .install_snapshot(&snapshot, SnapshotInstallMode::EmptyOnly)
            .unwrap();
        store.set_rules_digest(&snapshot.rules_digest).unwrap();

        for height in 2..=6u32 {
            let parent = store.tip().unwrap().unwrap();
            let tree = store.tree().unwrap();
            let nf_root = store.nullifier_root().unwrap();
            let nf_count = store.nullifier_count_at(&parent.hash).unwrap().unwrap();
            let mut header = empty_header(height, parent.hash, tree.root());
            bind_header_history(&store, &mut header);
            header.nullifier_root = nf_root;
            header.state_root = protocol::state::state_root(
                &snapshot.chain_id,
                height,
                tree.root(),
                tree.size(),
                nf_root,
                nf_count,
            );
            header.timestamp = u64::from(height);
            let block = Block::new(header, Vec::new());
            let transition = store
                .preview_nullifier_transition(parent.hash, &[])
                .unwrap();
            store
                .apply_with_nullifier_transition(
                    &block,
                    &tree,
                    &[u8::try_from(height).unwrap(); 32],
                    &transition,
                )
                .unwrap();
        }

        let parent_hash = store.hash_at(4).unwrap().unwrap();
        let tree = store.commitment_tree_at(&parent_hash).unwrap().unwrap();
        let nf_root = store.nullifier_root_at(&parent_hash).unwrap().unwrap();
        let nf_count = store.nullifier_count_at(&parent_hash).unwrap().unwrap();
        let mut side_header = empty_header(5, parent_hash, tree.root());
        bind_header_history(&store, &mut side_header);
        side_header.nullifier_root = nf_root;
        side_header.state_root = protocol::state::state_root(
            &snapshot.chain_id,
            5,
            tree.root(),
            tree.size(),
            nf_root,
            nf_count,
        );
        side_header.timestamp = 50;
        let side = Block::new(side_header, Vec::new());
        let transition = store
            .preview_nullifier_transition(parent_hash, &[])
            .unwrap();
        store
            .put_block_with_nullifier_transition(&side, &tree, &[99; 32], &transition)
            .unwrap();

        let orphan = Nullifier::from_base(&pallas::Base::from(99_999));
        let (_, _, orphan_nodes) = nullifier::build_set(&snapshot.chain_id, &[orphan]).unwrap();
        let tx = store.db.begin_write().unwrap();
        {
            let mut nodes = tx.open_table(NULLIFIER_NODES).unwrap();
            for (key, record) in orphan_nodes {
                nodes.insert(&key, record.encode().as_slice()).unwrap();
            }
        }
        tx.commit().unwrap();

        let before_nodes = store.db.begin_read().unwrap();
        let before_count = before_nodes
            .open_table(NULLIFIER_NODES)
            .unwrap()
            .len()
            .unwrap();
        drop(before_nodes);
        store.prune_branch_state(2, 4, &[]).unwrap();
        let after = store.db.begin_read().unwrap();
        let after_nodes = after.open_table(NULLIFIER_NODES).unwrap().len().unwrap();
        let branch_frontiers = after.open_table(BRANCH_FRONTIERS).unwrap();
        assert!(after_nodes < before_count);
        assert!(branch_frontiers
            .get(parent_hash.as_bytes())
            .unwrap()
            .is_some());
        assert!(branch_frontiers
            .get(side.hash().as_bytes())
            .unwrap()
            .is_some());
        assert!(branch_frontiers
            .get(&store.hash_at(3).unwrap().unwrap().as_bytes())
            .unwrap()
            .is_none());
        drop(after);

        let probe = Nullifier::from_base(&pallas::Base::from(123_456));
        let path = store
            .nullifier_non_membership_path(store.tip().unwrap().unwrap().hash, &probe)
            .unwrap()
            .unwrap();
        assert!(path.verifies(&snapshot.chain_id, store.nullifier_root().unwrap(), &probe));

        let reverted_tip = store.revert().unwrap();
        assert_eq!(reverted_tip.header().height, 6);
        let reverted_next = store.revert().unwrap();
        assert_eq!(reverted_next.header().height, 5);
        assert_eq!(store.tip().unwrap().unwrap().hash, parent_hash);
        store
            .apply_with_nullifier_transition(&side, &tree, &[99; 32], &transition)
            .unwrap();
        assert_eq!(store.tip().unwrap().unwrap().hash, side.hash());
        assert_eq!(store.nullifier_root().unwrap(), nf_root);

        // Long-running canonical growth retains only the branch state needed
        // for the configured rollback window, not one frontier per old block.
        for height in 6..=40u32 {
            let parent = store.tip().unwrap().unwrap();
            let tree = store.tree().unwrap();
            let root = store.nullifier_root().unwrap();
            let count = store.nullifier_count_at(&parent.hash).unwrap().unwrap();
            let mut header = empty_header(height, parent.hash, tree.root());
            bind_header_history(&store, &mut header);
            header.nullifier_root = root;
            header.state_root = protocol::state::state_root(
                &snapshot.chain_id,
                height,
                tree.root(),
                tree.size(),
                root,
                count,
            );
            header.timestamp = u64::from(height);
            let block = Block::new(header, Vec::new());
            let transition = store
                .preview_nullifier_transition(parent.hash, &[])
                .unwrap();
            store
                .apply_with_nullifier_transition(
                    &block,
                    &tree,
                    &[u8::try_from(height).unwrap(); 32],
                    &transition,
                )
                .unwrap();
            store
                .prune_branch_state(2, height.saturating_sub(2), &[(4, 6)])
                .unwrap();
        }
        let read = store.db.begin_read().unwrap();
        let frontier_heights: Vec<u32> = read
            .open_table(FRONTIERS)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| row.unwrap().0.value())
            .collect();
        assert!(
            frontier_heights.len() <= 7,
            "retained frontier heights: {frontier_heights:?}"
        );
        assert!(read.open_table(BRANCH_FRONTIERS).unwrap().len().unwrap() <= 6);
        assert!(read.open_table(NULLIFIER_ROOTS).unwrap().len().unwrap() <= 6);
        assert!(read.open_table(COMMITMENT_COUNTS).unwrap().len().unwrap() <= 6);
        let pinned_hash = store.hash_at(4).unwrap().unwrap();
        let expired_hash = store.hash_at(3).unwrap().unwrap();
        assert!(read
            .open_table(BRANCH_FRONTIERS)
            .unwrap()
            .get(pinned_hash.as_bytes())
            .unwrap()
            .is_some());
        assert!(read
            .open_table(BRANCH_FRONTIERS)
            .unwrap()
            .get(expired_hash.as_bytes())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_store_with_an_older_layout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.redb");
        {
            // A store written by code that recorded no layout version but
            // had already applied genesis.
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                meta.insert(TIP, &[0u8; 32]).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(Error::Corrupt(
                "store layout outdated; delete it and resync"
            ))
        ));
        let fresh = dir.path().join("fresh.redb");
        assert!(Store::open(&fresh).is_ok());
        assert!(Store::open(&fresh).is_ok(), "reopening keeps the version");
    }

    #[test]
    fn legacy_layouts_require_resync_even_if_the_version_matches() {
        let dir = tempfile::tempdir().unwrap();
        for version in [1u32, 2] {
            let path = dir.path().join(format!("old-{version}.redb"));
            let mut old_stamp = [0u8; 32];
            let domain = b"KRYPTOS:STORE:";
            old_stamp[..domain.len()].copy_from_slice(domain);
            old_stamp[domain.len()..domain.len() + 4].copy_from_slice(&version.to_le_bytes());
            {
                let db = Database::create(&path).unwrap();
                let tx = db.begin_write().unwrap();
                tx.open_table(META)
                    .unwrap()
                    .insert(SCHEMA, &old_stamp)
                    .unwrap();
                tx.commit().unwrap();
            }
            assert!(matches!(
                Store::open(path),
                Err(Error::Corrupt(
                    "store layout outdated; delete it and resync"
                ))
            ));
        }
    }

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("chain.redb")).unwrap();
        (dir, store)
    }

    fn anchor(v: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(v))
    }

    fn cmx(v: u64) -> protocol::coin::ExtractedCoinCommitment {
        protocol::coin::ExtractedCoinCommitment::from_bytes(&crypto::encoding::base_to_bytes(
            &pallas::Base::from(v),
        ))
        .unwrap()
    }

    fn bind_header_history(store: &Store, header: &mut BlockHeader) {
        if header.height > 0 {
            if let Ok(Some(frontier)) = store.header_frontier(&header.prev_hash) {
                header.history_root = frontier.root();
            }
        }
    }

    /// An empty block at `height` on top of `prev`.
    fn block(store: &Store, height: u32, prev: BlockHash) -> Block {
        let mut header: BlockHeader = empty_header(height, prev, anchor(u64::from(height)));
        bind_header_history(store, &mut header);
        header.timestamp = u64::from(height);
        Block::new(header, Vec::new())
    }

    #[test]
    fn fresh_store_has_no_tip_and_an_empty_tree() {
        let (_dir, store) = temp_store();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(store.hash_at(0).unwrap(), None);
        assert_eq!(
            store.nullifier_root().unwrap(),
            nullifier::empty_root(&[0; 32])
        );
    }

    #[test]
    fn roots_are_network_bound_and_remain_available_across_reverts() {
        let (_dir, store) = temp_store();
        let chain_id = [5u8; 32];
        store.set_chain_id(&chain_id).unwrap();
        assert_eq!(store.chain_id().unwrap(), chain_id);
        assert!(matches!(
            store.set_chain_id(&[6u8; 32]),
            Err(Error::Corrupt("store belongs to another network"))
        ));

        let genesis = block(&store, 0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        let child = block(&store, 1, genesis.hash());
        store
            .apply(&child, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert_eq!(
            store.nullifier_root().unwrap(),
            nullifier::empty_root(&chain_id)
        );
        assert_eq!(
            store.nullifier_root_at(&child.hash()).unwrap(),
            Some(nullifier::empty_root(&chain_id))
        );
        assert_eq!(store.nullifier_count_at(&child.hash()).unwrap(), Some(0));
        assert_eq!(store.commitment_count_at(&child.hash()).unwrap(), Some(0));
        assert_eq!(
            store.commitment_tree_at(&child.hash()).unwrap(),
            Some(CommitmentTree::empty())
        );

        store.revert().unwrap();
        assert_eq!(
            store.nullifier_root().unwrap(),
            nullifier::empty_root(&chain_id)
        );
        assert_eq!(
            store.nullifier_root_at(&child.hash()).unwrap(),
            Some(nullifier::empty_root(&chain_id))
        );
        assert_eq!(
            store.commitment_tree_at(&child.hash()).unwrap(),
            Some(CommitmentTree::empty())
        );
    }

    #[test]
    fn header_history_paths_follow_apply_revert_and_competing_children() {
        let (_dir, store) = temp_store();
        let tree = CommitmentTree::empty();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store.apply(&genesis, &tree, &[0; 32]).unwrap();
        let first = block(&store, 1, genesis.hash());
        store.apply(&first, &tree, &[1; 32]).unwrap();
        let second = block(&store, 2, first.hash());
        store.apply(&second, &tree, &[2; 32]).unwrap();

        let path = store.header_path(&second.hash(), 1).unwrap().unwrap();
        assert!(path.verify(first.header(), &second.header().history_root));
        assert!(store.header_path(&second.hash(), 2).unwrap().is_none());
        let original_frontier = store.header_frontier(&second.hash()).unwrap().unwrap();
        assert_eq!(original_frontier.count(), 3);

        store.revert().unwrap();
        assert_eq!(store.tip().unwrap().unwrap().hash, first.hash());
        assert_eq!(
            store.header_frontier(&second.hash()).unwrap(),
            Some(original_frontier)
        );
        let mut fork_header = second.header().clone();
        fork_header.timestamp += 1;
        let fork = Block::new(fork_header, Vec::new());
        store.apply(&fork, &tree, &[3; 32]).unwrap();
        let child = block(&store, 3, fork.hash());
        store.apply(&child, &tree, &[4; 32]).unwrap();

        let fork_path = store.header_path(&child.hash(), 2).unwrap().unwrap();
        assert!(fork_path.verify(fork.header(), &child.header().history_root));
        assert!(!fork_path.verify(second.header(), &child.header().history_root));
        assert_eq!(
            store
                .header_frontier(&child.hash())
                .unwrap()
                .unwrap()
                .count(),
            4
        );
    }

    #[test]
    fn invalid_body_or_history_root_cannot_partially_apply_a_block() {
        let (_dir, store) = temp_store();
        let tree = CommitmentTree::empty();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store.apply(&genesis, &tree, &[0; 32]).unwrap();
        let child = block(&store, 1, genesis.hash());

        for change_body in [false, true] {
            let mut header = child.header().clone();
            if change_body {
                header.body_root[0] ^= 1;
            } else {
                header.history_root[0] ^= 1;
            }
            let invalid = Block::new(header, Vec::new());
            assert!(store.apply(&invalid, &tree, &[1; 32]).is_err());
            assert_eq!(store.tip().unwrap().unwrap().hash, genesis.hash());
            assert!(store.block(&invalid.hash()).unwrap().is_none());
            assert!(store.header_frontier(&invalid.hash()).unwrap().is_none());
            assert_eq!(store.hash_at(1).unwrap(), None);
        }
    }

    #[test]
    fn side_branch_transition_persists_parent_specific_state() {
        let (_dir, store) = temp_store();
        let chain_id = [8u8; 32];
        store.set_chain_id(&chain_id).unwrap();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();

        let tree = CommitmentTree::empty();
        let mut header = protocol::block::empty_header(1, genesis.hash(), tree.root());
        bind_header_history(&store, &mut header);
        header.nullifier_root = nullifier::empty_root(&chain_id);
        let side = Block::new(header, vec![]);
        let transition = store
            .preview_nullifier_transition(genesis.hash(), &[])
            .unwrap();
        store
            .put_block_with_nullifier_transition(&side, &tree, &[1; 32], &transition)
            .unwrap();

        assert_eq!(
            store.nullifier_root_at(&side.hash()).unwrap(),
            Some(transition.root())
        );
        assert_eq!(
            store.nullifier_count_at(&side.hash()).unwrap(),
            Some(transition.count())
        );
        assert_eq!(store.commitment_count_at(&side.hash()).unwrap(), Some(0));
        assert_eq!(store.commitment_tree_at(&side.hash()).unwrap(), Some(tree));
        assert_eq!(store.tip().unwrap().unwrap().hash, genesis.hash());

        let descendant = store
            .preview_nullifier_transition(side.hash(), &[])
            .unwrap();
        assert_eq!(descendant.root(), transition.root());
    }

    #[test]
    fn apply_advances_the_tip_and_indexes_by_height() {
        let (_dir, store) = temp_store();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        let tip = store.tip().unwrap().unwrap();
        assert_eq!(
            tip,
            Tip {
                height: 0,
                hash: genesis.hash()
            }
        );
        assert_eq!(store.hash_at(0).unwrap(), Some(genesis.hash()));
        assert_eq!(store.block(&genesis.hash()).unwrap(), Some(genesis.clone()));

        let next = block(&store, 1, genesis.hash());
        store
            .apply(&next, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert_eq!(store.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn header_queries_match_bodies_and_distinguish_missing_from_corrupt() {
        let (_dir, store) = temp_store();
        let genesis = block(&store, 0, BlockHash::ZERO);
        let hash = genesis.hash();
        assert_eq!(store.header(&hash).unwrap(), None);
        assert!(!store.contains_block(&hash).unwrap());
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert_eq!(store.header(&hash).unwrap(), Some(genesis.header().clone()));
        assert!(store.contains_block(&hash).unwrap());

        // Header queries deliberately do not decode the body. Full reads still
        // detect truncation, so this optimization never certifies transactions.
        let header_len = genesis.header().encoded_len();
        let mut bytes = genesis.to_vec();
        bytes.truncate(header_len + 1);
        replace_block_bytes(&store, hash, &bytes);
        assert_eq!(store.header(&hash).unwrap(), Some(genesis.header().clone()));
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert!(store.block(&hash).is_err());

        replace_block_bytes(&store, hash, &bytes[..header_len - 1]);
        assert!(matches!(
            store.header(&hash),
            Err(Error::Corrupt("truncated block header"))
        ));
        assert!(store.contains_block(&hash).is_err());
        assert!(store.tip().is_err());

        let other = block(&store, 1, hash);
        replace_block_bytes(&store, hash, &other.to_vec());
        assert!(matches!(
            store.header(&hash),
            Err(Error::Corrupt("block header hash mismatch"))
        ));
        assert!(store.contains_block(&hash).is_err());
        assert!(store.tip().is_err());
    }

    fn replace_block_bytes(store: &Store, hash: BlockHash, bytes: &[u8]) {
        let tx = store.db.begin_write().unwrap();
        tx.open_table(BLOCKS)
            .unwrap()
            .insert(hash.as_bytes(), bytes)
            .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    #[ignore = "explicit local header/body decoding measurement"]
    fn measure_header_reads_against_full_block_decoding() {
        use std::hint::black_box;
        use std::time::Instant;
        const SAMPLES: u32 = 20;

        let (_dir, store) = temp_store();
        // A syntactically decodable maximum-shape body with dummy proofs and
        // signatures. This is not consensus-valid or a throughput benchmark.
        let count = protocol::consensus::MAX_ACTIONS;
        let mut bytes = protocol::bytes::Writer::default();
        bytes
            .put_u8(protocol::consensus::TX_VERSION)
            .put_u8(protocol::consensus::COINBASE_KIND)
            .put(&[0; 32])
            .put_u64_le(0)
            .put_u8(u8::try_from(count).unwrap());
        let rk = crypto::encoding::point_to_bytes(&crypto::curve::Generator::SpendAuth.point());
        for _ in 0..count {
            bytes
                .put(&[0; 32])
                .put(&rk)
                .put(&[0; 32])
                .put(&crypto::commitment::ValueCommitment::identity().to_bytes())
                .put_u8(protocol::encryption::ENCRYPTED_COIN_VERSION)
                .put(&vec![0; protocol::encryption::ENCRYPTED_COIN_LEN - 1]);
        }
        bytes
            .put(&vec![0; count * crypto::signature::SIGNATURE_LEN])
            .put(protocol::transaction::ACTION_PROOF_MAGIC)
            .put(&vec![0; protocol::consensus::proof_len(count).unwrap()])
            .put(&[0; crypto::signature::SIGNATURE_LEN]);
        let tx = Transaction::from_slice(&bytes.into_bytes()).unwrap();
        let transactions = vec![tx; protocol::consensus::MAX_BLOCK_TRANSACTIONS];
        let mut header = block(&store, 1, BlockHash::ZERO).header().clone();
        header.tx_root = protocol::block::tx_root(transactions.iter().map(Transaction::txid));
        header.body_root = protocol::body_tree::body_root(&transactions).unwrap();
        let large = Block::new(header, transactions);
        let hash = large.hash();
        store.put_block(&large, &[0; 32]).unwrap();
        assert_eq!(store.header(&hash).unwrap(), Some(large.header().clone()));
        assert_eq!(store.block(&hash).unwrap(), Some(large));

        let start = Instant::now();
        for _ in 0..SAMPLES {
            black_box(store.block(&hash).unwrap());
        }
        let bodies = start.elapsed();
        let start = Instant::now();
        for _ in 0..SAMPLES {
            black_box(store.header(&hash).unwrap());
        }
        let headers = start.elapsed();
        println!("header_read_measurement samples={SAMPLES} block_bytes={} full_body_total_us={} header_total_us={}",
            store.block_encoded_len(&hash).unwrap().unwrap(), bodies.as_micros(), headers.as_micros());
    }

    #[test]
    fn blocks_that_do_not_extend_the_tip_are_refused() {
        let (_dir, store) = temp_store();
        assert!(matches!(
            store.apply(
                &block(&store, 1, BlockHash::ZERO),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
        let genesis = block(&store, 0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert!(matches!(
            store.apply(
                &block(&store, 1, BlockHash::ZERO),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
        assert!(matches!(
            store.apply(
                &block(&store, 2, genesis.hash()),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
    }

    #[test]
    fn revert_restores_the_previous_tip_and_tree() {
        let (_dir, store) = temp_store();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        let mut tree = CommitmentTree::empty();
        tree.append(&cmx(1)).unwrap();
        let next = block(&store, 1, genesis.hash());
        store.apply(&next, &tree, &[2; 32]).unwrap();
        assert_eq!(store.chainwork(&next.hash()).unwrap(), Some([2; 32]));
        assert_eq!(store.tree().unwrap(), tree);

        let reverted = store.revert().unwrap();
        assert_eq!(store.chainwork(&next.hash()).unwrap(), Some([2; 32]));
        assert_eq!(reverted, next);
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(store.hash_at(1).unwrap(), None);
        assert!(
            store.block(&next.hash()).unwrap().is_some(),
            "block bytes are kept"
        );

        store.revert().unwrap();
        assert_eq!(store.tip().unwrap(), None);
        assert!(store.revert().is_err());
    }

    #[test]
    fn anchor_lookup_finds_recent_roots_only() {
        let (_dir, store) = temp_store();
        let mut prev = BlockHash::ZERO;
        let mut roots = Vec::new();
        for height in 0..5u32 {
            let mut tree = CommitmentTree::empty();
            for leaf in 0..=height {
                tree.append(&cmx(u64::from(leaf) + 1)).unwrap();
            }
            roots.push(tree.root());
            let b = block(&store, height, prev);
            prev = b.hash();
            store.apply(&b, &tree, &[0; 32]).unwrap();
        }
        assert_eq!(store.anchor_height(&roots[4], 10).unwrap(), Some(4));
        assert_eq!(store.anchor_height(&roots[1], 10).unwrap(), Some(1));
        assert_eq!(store.anchor_height(&roots[1], 2).unwrap(), None, "too old");
        assert_eq!(store.anchor_height(&anchor(999), 10).unwrap(), None);
    }

    #[test]
    fn block_state_checks_many_anchors_and_nullifiers_together() {
        let (_dir, store) = temp_store();
        let mut tree = CommitmentTree::empty();
        tree.append(&cmx(1)).unwrap();
        let first_root = tree.root();
        let genesis = block(&store, 0, BlockHash::ZERO);
        store.apply(&genesis, &tree, &[0; 32]).unwrap();
        tree.append(&cmx(2)).unwrap();
        let latest_root = tree.root();
        store
            .apply(&block(&store, 1, genesis.hash()), &tree, &[0; 32])
            .unwrap();

        assert_eq!(
            store.check_block_state(&[latest_root], &[], 0).unwrap(),
            None
        );
        assert_eq!(
            store.check_block_state(&[first_root], &[], 0).unwrap(),
            Some(BlockStateViolation::UnknownOrStaleAnchor)
        );
        assert_eq!(
            store.check_block_state(&[first_root], &[], 1).unwrap(),
            None
        );

        let spent = Nullifier::from_base(&pallas::Base::from(77u64));
        let write = store.db.begin_write().unwrap();
        write
            .open_table(NULLIFIERS)
            .unwrap()
            .insert(&spent.to_bytes(), 0)
            .unwrap();
        write.commit().unwrap();
        assert_eq!(
            store
                .check_block_state(&[latest_root], &[spent], 1)
                .unwrap(),
            Some(BlockStateViolation::NullifierAlreadySpent)
        );
    }

    #[test]
    fn pruned_frontiers_are_gone_and_recent_ones_stay() {
        let (_dir, store) = temp_store();
        let mut prev = BlockHash::ZERO;
        for height in 0..4u32 {
            let b = block(&store, height, prev);
            prev = b.hash();
            store.apply(&b, &CommitmentTree::empty(), &[0; 32]).unwrap();
        }
        store.prune_frontiers_below(2).unwrap();
        assert!(store.tree_at(1).unwrap().is_none());
        assert!(store.tree_at(2).unwrap().is_some());
        assert!(store.tree().is_ok(), "the tip frontier is kept");
    }

    /// Measures nullifier inserts and lookups at scale. Run with
    /// `cargo test --release -p storage nullifier_lookup_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn nullifier_lookup_cost() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("bench.redb")).unwrap();
        let count = 1_000_000u64;
        let key_of = |i: u64| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&i.to_le_bytes());
            key
        };
        let started = std::time::Instant::now();
        let tx = store.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(NULLIFIERS).unwrap();
            for i in 0..count {
                table.insert(&key_of(i), 1u32).unwrap();
            }
        }
        tx.commit().unwrap();
        let inserted = started.elapsed();
        let started = std::time::Instant::now();
        let mut hits = 0;
        for i in 0..100_000u64 {
            let nf = Nullifier::from_bytes(&key_of(i * 7)).unwrap();
            if store.contains_nullifier(&nf).unwrap() {
                hits += 1;
            }
        }
        let looked_up = started.elapsed();
        eprintln!("insert {count}: {inserted:?}; 100000 lookups: {looked_up:?} ({hits} hits)");
    }

    #[test]
    fn put_block_stores_bytes_without_moving_the_tip() {
        let (_dir, store) = temp_store();
        let side = block(&store, 5, BlockHash::from_bytes([9; 32]));
        assert_eq!(store.block_encoded_len(&side.hash()).unwrap(), None);
        store.put_block(&side, &[7; 32]).unwrap();
        assert_eq!(
            store.block_encoded_len(&side.hash()).unwrap(),
            Some(side.to_vec().len())
        );
        assert_eq!(store.chainwork(&side.hash()).unwrap(), Some([7; 32]));
        assert_eq!(store.block(&side.hash()).unwrap(), Some(side));
        assert_eq!(store.tip().unwrap(), None);
    }

    #[test]
    fn store_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let (genesis, next, side) = {
            let store = Store::open(&path).unwrap();
            let genesis = block(&store, 0, BlockHash::ZERO);
            store
                .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
                .unwrap();
            let next = block(&store, 1, genesis.hash());
            store
                .apply(&next, &CommitmentTree::empty(), &[2; 32])
                .unwrap();
            let mut side_header = next.header().clone();
            side_header.timestamp += 1;
            let side = Block::new(side_header, Vec::new());
            store.put_block(&side, &[3; 32]).unwrap();
            (genesis, next, side)
        };
        let store = Store::open(&path).unwrap();
        assert_eq!(store.tip().unwrap().unwrap().hash, next.hash());
        assert_eq!(store.chainwork(&genesis.hash()).unwrap(), Some([0; 32]));
        assert_eq!(store.chainwork(&next.hash()).unwrap(), Some([2; 32]));
        assert_eq!(store.chainwork(&side.hash()).unwrap(), Some([3; 32]));
    }
}
