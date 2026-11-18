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

use std::collections::HashSet;
use std::path::Path;

use protocol::block::{Block, BlockHash, BlockHeader, HEADER_LEN};
use protocol::bytes::Encodable;
use protocol::consensus::next_height;
use protocol::nullifier::Nullifier;
use protocol::transaction::{Anchor, Transaction, TxId};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::tree::CommitmentTree;
use crate::{Error, Result};

const BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blocks");
const CHAINWORK: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("chainwork");
const HEIGHTS: TableDefinition<u32, &[u8; 32]> = TableDefinition::new("heights");
const NULLIFIERS: TableDefinition<&[u8; 32], u32> = TableDefinition::new("nullifiers");
const FRONTIERS: TableDefinition<u32, &[u8]> = TableDefinition::new("frontiers");
const META: TableDefinition<&str, &[u8; 32]> = TableDefinition::new("meta");
/// Transaction id to its location, `LE32(height) || LE32(index)`.
const TXIDS: TableDefinition<&[u8; 32], &[u8; 8]> = TableDefinition::new("txids");

/// Meta key of the tip hash.
const TIP: &str = "tip";
/// Meta key of the consensus rules digest the store was built under.
const RULES: &str = "rules";
/// Meta key of the on-disk layout version.
const SCHEMA: &str = "schema";
/// The on-disk layout this code writes and reads. Bumped whenever a table
/// is added or changed; an older store is refused rather than served with
/// tables it never filled.
pub const SCHEMA_VERSION: u32 = 1;

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
#[derive(Debug)]
pub struct Store {
    db: Database,
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
        tx.open_table(CHAINWORK)?;
        tx.open_table(HEIGHTS)?;
        tx.open_table(NULLIFIERS)?;
        tx.open_table(FRONTIERS)?;
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
        Ok(Self { db })
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
        let bytes = blocks
            .get(hash.as_bytes())?
            .ok_or(Error::Corrupt("tip block missing"))?;
        let header = decode_header(bytes.value(), &hash)?;
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
        blocks
            .get(hash.as_bytes())?
            .map(|bytes| decode_header(bytes.value(), hash))
            .transpose()
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
        let tip_block = blocks
            .get(tip_hash.as_bytes())?
            .ok_or(Error::Corrupt("tip block missing"))?;
        let tip_height = decode_header(tip_block.value(), &tip_hash)?.height;
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
        if tx.open_table(META)?.get("reorg_original")?.is_some() {
            return Ok(());
        }
        {
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.retain(|h, _| h >= height)?;
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
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(block.hash().as_bytes(), block.to_vec().as_slice())?;
            tx.open_table(CHAINWORK)?
                .insert(block.hash().as_bytes(), chainwork)?;
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
        let header = block.header();
        let expected_prev = match self.tip()? {
            Some(t) => (t.hash, next_height(t.height)?),
            None => (BlockHash::ZERO, 0),
        };
        if (header.prev_hash, header.height) != expected_prev {
            return Err(Error::NotOnTip);
        }
        let hash = block.hash();
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(hash.as_bytes(), block.to_vec().as_slice())?;
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

/// Decode only the fixed-size header while checking its storage-key identity.
fn decode_header(bytes: &[u8], hash: &BlockHash) -> Result<BlockHeader> {
    let prefix = bytes
        .get(..HEADER_LEN)
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
    const SCHEMA_DOMAIN: &[u8] = b"RHOMBUS:CHAINSTORE:";
    out[..SCHEMA_DOMAIN.len()].copy_from_slice(SCHEMA_DOMAIN);
    out[SCHEMA_DOMAIN.len()..SCHEMA_DOMAIN.len() + 4]
        .copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
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
            old_stamp[..14].copy_from_slice(b"RHOMBUS:STORE:");
            old_stamp[14..18].copy_from_slice(&version.to_le_bytes());
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

    /// An empty block at `height` on top of `prev`.
    fn block(height: u32, prev: BlockHash) -> Block {
        let mut header: BlockHeader = empty_header(height, prev, anchor(u64::from(height)));
        header.timestamp = u64::from(height);
        Block::new(header, Vec::new())
    }

    #[test]
    fn fresh_store_has_no_tip_and_an_empty_tree() {
        let (_dir, store) = temp_store();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(store.hash_at(0).unwrap(), None);
    }

    #[test]
    fn apply_advances_the_tip_and_indexes_by_height() {
        let (_dir, store) = temp_store();
        let genesis = block(0, BlockHash::ZERO);
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

        let next = block(1, genesis.hash());
        store
            .apply(&next, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert_eq!(store.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn header_queries_match_bodies_and_distinguish_missing_from_corrupt() {
        let (_dir, store) = temp_store();
        let genesis = block(0, BlockHash::ZERO);
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
        let mut bytes = genesis.to_vec();
        bytes.truncate(HEADER_LEN + 1);
        replace_block_bytes(&store, hash, &bytes);
        assert_eq!(store.header(&hash).unwrap(), Some(genesis.header().clone()));
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert!(store.block(&hash).is_err());

        replace_block_bytes(&store, hash, &bytes[..HEADER_LEN - 1]);
        assert!(matches!(
            store.header(&hash),
            Err(Error::Corrupt("truncated block header"))
        ));
        assert!(store.contains_block(&hash).is_err());
        assert!(store.tip().is_err());

        let other = block(1, hash);
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
        let mut header = block(1, BlockHash::ZERO).header().clone();
        header.tx_root = protocol::block::tx_root(transactions.iter().map(Transaction::txid));
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
                &block(1, BlockHash::ZERO),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
        let genesis = block(0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        assert!(matches!(
            store.apply(
                &block(1, BlockHash::ZERO),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
        assert!(matches!(
            store.apply(
                &block(2, genesis.hash()),
                &CommitmentTree::empty(),
                &[0; 32]
            ),
            Err(Error::NotOnTip)
        ));
    }

    #[test]
    fn revert_restores_the_previous_tip_and_tree() {
        let (_dir, store) = temp_store();
        let genesis = block(0, BlockHash::ZERO);
        store
            .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        let mut tree = CommitmentTree::empty();
        tree.append(&cmx(1)).unwrap();
        let next = block(1, genesis.hash());
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
            let b = block(height, prev);
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
        let genesis = block(0, BlockHash::ZERO);
        store.apply(&genesis, &tree, &[0; 32]).unwrap();
        tree.append(&cmx(2)).unwrap();
        let latest_root = tree.root();
        store
            .apply(&block(1, genesis.hash()), &tree, &[0; 32])
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
            let b = block(height, prev);
            prev = b.hash();
            store.apply(&b, &CommitmentTree::empty(), &[0; 32]).unwrap();
        }
        store.prune_frontiers_below(2).unwrap();
        assert!(store.tree_at(1).unwrap().is_none());
        assert!(store.tree_at(2).unwrap().is_some());
        assert!(store.tree().is_ok(), "the tip frontier is kept");
    }

    /// Measures nullifier inserts and lookups at scale. Run with
    /// `cargo test --release -p rhombus-storage nullifier_lookup_cost -- --ignored --nocapture`.
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
        let side = block(5, BlockHash::from_bytes([9; 32]));
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
        let genesis = block(0, BlockHash::ZERO);
        let next = block(1, genesis.hash());
        let side = block(2, genesis.hash());
        {
            let store = Store::open(&path).unwrap();
            store
                .apply(&genesis, &CommitmentTree::empty(), &[0; 32])
                .unwrap();
            store
                .apply(&next, &CommitmentTree::empty(), &[2; 32])
                .unwrap();
            store.put_block(&side, &[3; 32]).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.tip().unwrap().unwrap().hash, next.hash());
        assert_eq!(store.chainwork(&genesis.hash()).unwrap(), Some([0; 32]));
        assert_eq!(store.chainwork(&next.hash()).unwrap(), Some([2; 32]));
        assert_eq!(store.chainwork(&side.hash()).unwrap(), Some([3; 32]));
    }
}
