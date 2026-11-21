//! Snapshot manifests and trust-anchor checks.
//!
//! A snapshot is a state transfer format, not evidence that the state was
//! reached from genesis. Until HistoryStep exists, an importer must match the
//! snapshot to an exact, locally configured checkpoint.

use protocol::block::{BlockHash, BlockHeader};
use protocol::bytes::{Encodable, Reader, Writer};
use protocol::header_tree::HeaderFrontier;
use protocol::nullifier::Nullifier;
use protocol::transaction::Anchor;

use crate::params::ChainParams;
use crate::target::ChainWork;

/// Current snapshot manifest encoding version.
pub const SNAPSHOT_ENCODING_VERSION: u16 = 1;
const MANIFEST_MAGIC: &[u8; 4] = b"RHN1";
// The canonical depth-32 frontier has at most 33 digests, count, tip and version.
const MAX_HEADER_FRONTIER_LEN: usize = 1_100;

/// The roots and sizes of a materialized chain state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotRoots {
    /// Note commitment tree root.
    pub commitment_root: Anchor,
    /// Number of note commitments.
    pub commitment_count: u64,
    /// Spent-nullifier sparse-tree root.
    pub nullifier_root: Anchor,
    /// Number of spent nullifiers.
    pub nullifier_count: u64,
    /// Composite commitment over the complete state.
    pub state_root: Anchor,
}

/// A versioned description of one exact state snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Genesis block hash identifying the chain and sparse-tree domain.
    pub chain_id: [u8; 32],
    /// Consensus rules digest that validated the snapshot state.
    pub rules_digest: [u8; 32],
    /// Snapshot height.
    pub height: u32,
    /// Hash of the block at `height`.
    pub block_hash: BlockHash,
    /// Cumulative validated proof of work, big-endian U256.
    pub chainwork: [u8; 32],
    /// State roots and their leaf counts.
    pub roots: SnapshotRoots,
    /// Canonical snapshot payload length, in bytes.
    pub payload_len: u64,
    /// Encoding version for the state payload.
    pub encoding_version: u16,
}

/// A header in the history suffix needed to resume DAA and time validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotHeaderState {
    /// The canonical block header.
    pub header: BlockHeader,
    /// Number of note commitments after this header.
    pub commitment_count: u64,
    /// Spent-nullifier count after this header, used to recompute state_root.
    pub nullifier_count: u64,
    /// Cumulative validated work after this header, big-endian U256.
    pub chainwork: [u8; 32],
}

/// A retained note-tree frontier at one authenticated height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFrontier {
    /// Height for this frontier.
    pub height: u32,
    /// Canonical encoded `CommitmentTree`.
    pub bytes: Vec<u8>,
}

/// Snapshot payload needed to resume local validation from a checkpoint.
///
/// This format carries the authenticated header suffix, retained commitment
/// frontiers, and sorted nullifier set. A receiver recomputes all roots before
/// installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotPayload {
    /// The manifest describing this payload.
    pub manifest: SnapshotManifest,
    /// Header-tree state immediately before the first retained suffix header.
    /// Older subtrees may remain opaque; the suffix binds this prefix to the
    /// configured checkpoint without requiring every historical header.
    pub header_frontier: HeaderFrontier,
    /// Contiguous header suffix, ending at the snapshot block.
    pub recent_headers: Vec<SnapshotHeaderState>,
    /// Contiguous retained frontiers matching the header suffix.
    pub anchor_frontiers: Vec<SnapshotFrontier>,
    /// Every spent nullifier, in strictly increasing canonical byte order.
    pub nullifiers: Vec<Nullifier>,
}

/// Why an unproven snapshot could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// No locally configured checkpoint exists at this snapshot height.
    #[error("snapshot height has no configured checkpoint")]
    NoCheckpoint,
    /// The checkpoint, header, manifest, or expected chain metadata disagree.
    #[error("snapshot does not match its configured checkpoint")]
    CheckpointMismatch,
    /// The snapshot encoding version is unsupported.
    #[error("unsupported snapshot encoding version")]
    EncodingVersion,
    /// The payload's canonical encoded length differs from the manifest.
    #[error("snapshot payload length mismatch")]
    PayloadLength,
    /// The commitment frontier is malformed or does not match its manifest.
    #[error("snapshot commitment frontier mismatch")]
    CommitmentTree,
    /// The nullifier list is unsorted, duplicated, or does not match its root.
    #[error("snapshot nullifier set mismatch")]
    NullifierSet,
    /// Header suffix or retained frontier sequence is incomplete or invalid.
    #[error("snapshot history suffix mismatch")]
    HeaderHistory,
}

fn encoded_payload_len(
    header_frontier: &HeaderFrontier,
    recent_headers: &[SnapshotHeaderState],
    anchor_frontiers: &[SnapshotFrontier],
    nullifiers: &[Nullifier],
) -> Option<usize> {
    let prefix_len = header_frontier.to_vec().len();
    if prefix_len > MAX_HEADER_FRONTIER_LEN {
        return None;
    }
    let mut len = 4usize.checked_add(prefix_len)?.checked_add(4)?;
    for entry in recent_headers {
        len = len
            .checked_add(4)?
            .checked_add(entry.header.encoded_len())?
            .checked_add(8 + 8 + 32)?;
    }
    len = len.checked_add(4)?;
    for frontier in anchor_frontiers {
        len = len.checked_add(4 + 4)?.checked_add(frontier.bytes.len())?;
    }
    len.checked_add(8)?
        .checked_add(nullifiers.len().checked_mul(32)?)
}

impl SnapshotManifest {
    /// Creates a manifest for a payload, measuring its canonical payload size.
    pub fn for_payload(
        chain_id: [u8; 32],
        rules_digest: [u8; 32],
        height: u32,
        block_hash: BlockHash,
        chainwork: ChainWork,
        roots: SnapshotRoots,
        header_frontier: &HeaderFrontier,
        recent_headers: &[SnapshotHeaderState],
        anchor_frontiers: &[SnapshotFrontier],
        nullifiers: &[Nullifier],
    ) -> Option<Self> {
        let payload_len = encoded_payload_len(
            header_frontier,
            recent_headers,
            anchor_frontiers,
            nullifiers,
        )?;
        Some(Self {
            chain_id,
            rules_digest,
            height,
            block_hash,
            chainwork: chainwork.to_be_bytes(),
            roots,
            payload_len: u64::try_from(payload_len).ok()?,
            encoding_version: SNAPSHOT_ENCODING_VERSION,
        })
    }

    /// Encodes the manifest canonically.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4 + 2 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 32 + 8 + 32 + 8);
        w.put(MANIFEST_MAGIC)
            .put(&self.encoding_version.to_le_bytes())
            .put(&self.chain_id)
            .put(&self.rules_digest)
            .put(&self.height.to_le_bytes())
            .put(self.block_hash.as_bytes())
            .put(&self.chainwork)
            .put(&self.roots.commitment_root.to_bytes())
            .put(&self.roots.commitment_count.to_le_bytes())
            .put(&self.roots.nullifier_root.to_bytes())
            .put(&self.roots.nullifier_count.to_le_bytes())
            .put(&self.roots.state_root.to_bytes())
            .put(&self.payload_len.to_le_bytes());
        w.into_bytes()
    }

    /// Decodes a canonical manifest and rejects trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, protocol::Error> {
        let mut r = Reader::new(bytes);
        if &r.take_array::<4>()? != MANIFEST_MAGIC {
            return Err(protocol::Error::Malformed("snapshot manifest magic"));
        }
        let encoding_version = u16::from_le_bytes(r.take_array()?);
        let chain_id = r.take_array()?;
        let rules_digest = r.take_array()?;
        let height = u32::from_le_bytes(r.take_array()?);
        let block_hash = BlockHash::from_bytes(r.take_array()?);
        let chainwork = r.take_array()?;
        let commitment_root = Anchor::read(&mut r)?;
        let commitment_count = r.take_u64_le()?;
        let nullifier_root = Anchor::read(&mut r)?;
        let nullifier_count = r.take_u64_le()?;
        let state_root = Anchor::read(&mut r)?;
        let payload_len = r.take_u64_le()?;
        r.finish()?;
        Ok(Self {
            chain_id,
            rules_digest,
            height,
            block_hash,
            chainwork,
            roots: SnapshotRoots {
                commitment_root,
                commitment_count,
                nullifier_root,
                nullifier_count,
                state_root,
            },
            payload_len,
            encoding_version,
        })
    }
}

impl SnapshotPayload {
    /// Converts a payload that has passed `verify_snapshot` into the storage
    /// installer DTO. Callers must perform checkpoint verification first.
    pub fn to_storage_install(&self) -> crate::Result<storage::store::SnapshotInstall> {
        let checkpoint_work = crate::target::ChainWork::from_be_bytes(self.manifest.chainwork);
        let mut work = checkpoint_work;
        let mut entries = Vec::with_capacity(self.recent_headers.len());
        for (entry, frontier) in self.recent_headers.iter().zip(&self.anchor_frontiers).rev() {
            entries.push(storage::store::SnapshotHeader {
                header: entry.header.clone(),
                commitment_count: entry.commitment_count,
                nullifier_count: entry.nullifier_count,
                frontier: frontier.bytes.clone(),
                chainwork: work.to_be_bytes(),
            });
            if entry.header.height > 0 {
                let block_work = crate::target::Target::from_compact(entry.header.target)?
                    .work()?
                    .as_u256();
                let remaining = work
                    .as_u256()
                    .checked_sub(block_work)
                    .ok_or(crate::Error::InvalidBlock("snapshot work underflow"))?;
                work = crate::target::ChainWork::from_u256(remaining);
            }
        }
        entries.reverse();
        Ok(storage::store::SnapshotInstall {
            chain_id: self.manifest.chain_id,
            rules_digest: self.manifest.rules_digest,
            checkpoint: storage::store::SnapshotCheckpoint {
                height: self.manifest.height,
                hash: self.manifest.block_hash,
                work: checkpoint_work.to_be_bytes(),
                state_root: self.manifest.roots.state_root,
            },
            header_frontier: self.header_frontier.clone(),
            headers: entries,
            nullifiers: self.nullifiers.clone(),
        })
    }

    /// Builds a snapshot for the current canonical tip from the local store.
    ///
    /// This creates an artifact; it does not assert that peers should trust it.
    /// Import still requires checkpoint binding and complete root validation.
    pub fn from_store(
        store: &storage::store::Store,
        params: &ChainParams,
        chain_id: &[u8; 32],
    ) -> crate::Result<Self> {
        let tip = store
            .tip()?
            .ok_or(crate::Error::InvalidBlock("no snapshot tip"))?;
        Self::build_from_store_height(store, params, chain_id, tip.height, false)
    }

    /// Builds the exact canonical state at a configured checkpoint, even if
    /// the serving node has advanced beyond it. The chain retains the small
    /// header/frontier suffix needed for this export.
    pub fn from_store_at(
        store: &storage::store::Store,
        params: &ChainParams,
        chain_id: &[u8; 32],
        height: u32,
    ) -> crate::Result<Self> {
        if params.checkpoint_at(height).is_none() {
            return Err(crate::Error::InvalidBlock("snapshot checkpoint missing"));
        }
        Self::build_from_store_height(store, params, chain_id, height, true)
    }

    fn build_from_store_height(
        store: &storage::store::Store,
        params: &ChainParams,
        chain_id: &[u8; 32],
        height: u32,
        require_checkpoint: bool,
    ) -> crate::Result<Self> {
        if store.chain_id()? != *chain_id {
            return Err(crate::Error::InvalidBlock("snapshot chain id mismatch"));
        }
        let tip_hash = store
            .hash_at(height)?
            .ok_or(crate::Error::InvalidBlock("snapshot height missing"))?;
        let checkpoint_header = store.header(&tip_hash)?.ok_or(crate::Error::InvalidBlock(
            "snapshot checkpoint header missing",
        ))?;
        let chainwork = ChainWork::from_be_bytes(
            store
                .chainwork(&tip_hash)?
                .ok_or(crate::Error::InvalidBlock("snapshot chainwork missing"))?,
        );
        if let Some(checkpoint) = params.checkpoint_at(height) {
            if !checkpoint.matches(&checkpoint_header, chainwork) {
                return Err(crate::Error::InvalidBlock(
                    "snapshot checkpoint conflicts with configured profile",
                ));
            }
        } else if require_checkpoint {
            return Err(crate::Error::InvalidBlock("snapshot checkpoint missing"));
        }
        let nullifiers = store.export_nullifiers_at(height)?;
        let nullifier_root = storage::nullifier::root_from_set(chain_id, &nullifiers)?;
        let nullifier_count = u64::try_from(nullifiers.len())
            .map_err(|_| crate::Error::InvalidBlock("snapshot nullifier count overflow"))?;
        if store.nullifier_root_at(&tip_hash)? != Some(nullifier_root)
            || store.nullifier_count_at(&tip_hash)? != Some(nullifier_count)
        {
            return Err(crate::Error::InvalidBlock(
                "historical snapshot nullifier state unavailable",
            ));
        }
        let rules_digest = store.rules_digest()?.ok_or(crate::Error::RulesMismatch)?;
        let suffix = crate::validate::frontier_retention(params)
            .max(u32::try_from(crate::validate::header_lookback(params)).unwrap_or(u32::MAX));
        let first_height = height.saturating_sub(suffix);
        let header_frontier = if first_height == 0 {
            HeaderFrontier::empty()
        } else {
            let first_hash = store
                .hash_at(first_height)?
                .ok_or(crate::Error::InvalidBlock(
                    "snapshot first suffix header missing",
                ))?;
            let first_header = store
                .header(&first_hash)?
                .ok_or(crate::Error::InvalidBlock(
                    "snapshot first suffix header missing",
                ))?;
            let prefix_hash = first_header.prev_hash;
            store
                .header_frontier(&prefix_hash)?
                .ok_or(crate::Error::InvalidBlock(
                    "snapshot header frontier missing",
                ))?
        };
        let mut recent_headers = Vec::new();
        let mut anchor_frontiers = Vec::new();
        for entry_height in first_height..=height {
            let hash = store
                .hash_at(entry_height)?
                .ok_or(crate::Error::InvalidBlock("snapshot suffix height missing"))?;
            let header = store
                .header(&hash)?
                .ok_or(crate::Error::InvalidBlock("snapshot suffix header missing"))?;
            let tree = store
                .tree_at(entry_height)?
                .ok_or(crate::Error::InvalidBlock(
                    "snapshot anchor frontier missing",
                ))?;
            let block_nullifier_count =
                store
                    .nullifier_count_at(&hash)?
                    .ok_or(crate::Error::InvalidBlock(
                        "snapshot nullifier count missing",
                    ))?;
            let block_chainwork = store
                .chainwork(&hash)?
                .ok_or(crate::Error::InvalidBlock("snapshot suffix work missing"))?;
            recent_headers.push(SnapshotHeaderState {
                header,
                commitment_count: tree.size(),
                nullifier_count: block_nullifier_count,
                chainwork: block_chainwork,
            });
            anchor_frontiers.push(SnapshotFrontier {
                height: entry_height,
                bytes: tree.to_vec(),
            });
        }
        let tree = store.tree_at(height)?.ok_or(crate::Error::InvalidBlock(
            "snapshot checkpoint frontier missing",
        ))?;
        let header = recent_headers
            .last()
            .map(|entry| &entry.header)
            .ok_or(crate::Error::InvalidBlock("snapshot suffix empty"))?;
        let legacy_genesis = height == 0;
        let state_root = if legacy_genesis {
            header.state_root
        } else {
            crate::state::state_root(
                chain_id,
                height,
                tree.root(),
                tree.size(),
                nullifier_root,
                nullifier_count,
            )
        };
        if header.commitment_root != tree.root()
            || (!legacy_genesis && header.nullifier_root != nullifier_root)
            || header.state_root != state_root
        {
            return Err(crate::Error::InvalidBlock("snapshot state root mismatch"));
        }
        if store.hash_at(height)? != Some(tip_hash) {
            return Err(crate::Error::InvalidBlock(
                "canonical checkpoint changed during snapshot export",
            ));
        }
        let manifest = SnapshotManifest::for_payload(
            *chain_id,
            rules_digest,
            height,
            tip_hash,
            chainwork,
            SnapshotRoots {
                commitment_root: tree.root(),
                commitment_count: tree.size(),
                nullifier_root,
                nullifier_count,
                state_root,
            },
            &header_frontier,
            &recent_headers,
            &anchor_frontiers,
            &nullifiers,
        )
        .ok_or(crate::Error::InvalidBlock(
            "snapshot payload length overflow",
        ))?;
        let payload = Self {
            manifest,
            header_frontier,
            recent_headers,
            anchor_frontiers,
            nullifiers,
        };
        verify_payload(&payload, chain_id)
            .map_err(|_| crate::Error::InvalidBlock("snapshot payload root mismatch"))?;
        payload
            .to_bytes()
            .map_err(|_| crate::Error::InvalidBlock("snapshot payload encoding failure"))?;
        Ok(payload)
    }

    /// Canonical payload bytes: headers with cardinalities, retained frontiers,
    /// then sorted canonical nullifiers.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SnapshotError> {
        let capacity = encoded_payload_len(
            &self.header_frontier,
            &self.recent_headers,
            &self.anchor_frontiers,
            &self.nullifiers,
        )
        .ok_or(SnapshotError::PayloadLength)?;
        let header_count =
            u32::try_from(self.recent_headers.len()).map_err(|_| SnapshotError::PayloadLength)?;
        let frontier_count =
            u32::try_from(self.anchor_frontiers.len()).map_err(|_| SnapshotError::PayloadLength)?;
        let nullifier_count =
            u64::try_from(self.nullifiers.len()).map_err(|_| SnapshotError::PayloadLength)?;
        let mut w = Writer::with_capacity(capacity);
        let prefix = self.header_frontier.to_vec();
        let prefix_len = u32::try_from(prefix.len()).map_err(|_| SnapshotError::PayloadLength)?;
        w.put(&prefix_len.to_le_bytes()).put(&prefix);
        w.put(&header_count.to_le_bytes());
        for entry in &self.recent_headers {
            let bytes = entry.header.to_vec();
            let header_len =
                u32::try_from(bytes.len()).map_err(|_| SnapshotError::PayloadLength)?;
            w.put(&header_len.to_le_bytes())
                .put(&bytes)
                .put(&entry.commitment_count.to_le_bytes())
                .put(&entry.nullifier_count.to_le_bytes())
                .put(&entry.chainwork);
        }
        w.put(&frontier_count.to_le_bytes());
        for frontier in &self.anchor_frontiers {
            let bytes_len =
                u32::try_from(frontier.bytes.len()).map_err(|_| SnapshotError::PayloadLength)?;
            w.put(&frontier.height.to_le_bytes())
                .put(&bytes_len.to_le_bytes())
                .put(&frontier.bytes);
        }
        w.put(&nullifier_count.to_le_bytes());
        for nullifier in &self.nullifiers {
            w.put(&nullifier.to_bytes());
        }
        let bytes = w.into_bytes();
        if u64::try_from(bytes.len()).ok() != Some(self.manifest.payload_len) {
            return Err(SnapshotError::PayloadLength);
        }
        Ok(bytes)
    }

    /// Decodes a complete payload after checking fixed-width counts against
    /// the manifest before allocating the nullifier vector.
    pub fn from_bytes(
        manifest: SnapshotManifest,
        bytes: &[u8],
        max_payload_len: u64,
    ) -> Result<Self, SnapshotError> {
        if manifest.encoding_version != SNAPSHOT_ENCODING_VERSION {
            return Err(SnapshotError::EncodingVersion);
        }
        if manifest.payload_len > max_payload_len
            || u64::try_from(bytes.len()).ok() != Some(manifest.payload_len)
        {
            return Err(SnapshotError::PayloadLength);
        }
        let mut r = Reader::new(bytes);
        let prefix_len = usize::try_from(u32::from_le_bytes(
            r.take_array().map_err(|_| SnapshotError::PayloadLength)?,
        ))
        .map_err(|_| SnapshotError::PayloadLength)?;
        if prefix_len > MAX_HEADER_FRONTIER_LEN {
            return Err(SnapshotError::HeaderHistory);
        }
        let prefix_bytes = r
            .take(prefix_len)
            .map_err(|_| SnapshotError::HeaderHistory)?;
        let header_frontier =
            HeaderFrontier::from_slice(prefix_bytes).map_err(|_| SnapshotError::HeaderHistory)?;
        let header_count = usize::try_from(u32::from_le_bytes(
            r.take_array().map_err(|_| SnapshotError::PayloadLength)?,
        ))
        .map_err(|_| SnapshotError::PayloadLength)?;
        let min_header_record = 4usize
            .checked_add(protocol::block::HEADER_LEN_V1)
            .and_then(|n| n.checked_add(48))
            .ok_or(SnapshotError::PayloadLength)?;
        let max_header_count = r
            .remaining()
            .checked_div(min_header_record)
            .ok_or(SnapshotError::PayloadLength)?;
        if header_count > max_header_count {
            return Err(SnapshotError::HeaderHistory);
        }
        let mut recent_headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let header_len = usize::try_from(u32::from_le_bytes(
                r.take_array().map_err(|_| SnapshotError::PayloadLength)?,
            ))
            .map_err(|_| SnapshotError::PayloadLength)?;
            if header_len > r.remaining().saturating_sub(48) {
                return Err(SnapshotError::HeaderHistory);
            }
            let header_bytes = r
                .take(header_len)
                .map_err(|_| SnapshotError::HeaderHistory)?;
            let header =
                BlockHeader::from_slice(header_bytes).map_err(|_| SnapshotError::HeaderHistory)?;
            recent_headers.push(SnapshotHeaderState {
                header,
                commitment_count: r.take_u64_le().map_err(|_| SnapshotError::HeaderHistory)?,
                nullifier_count: r.take_u64_le().map_err(|_| SnapshotError::HeaderHistory)?,
                chainwork: r.take_array().map_err(|_| SnapshotError::HeaderHistory)?,
            });
        }
        let frontier_count = usize::try_from(u32::from_le_bytes(
            r.take_array().map_err(|_| SnapshotError::PayloadLength)?,
        ))
        .map_err(|_| SnapshotError::PayloadLength)?;
        if frontier_count > r.remaining() / 9 {
            return Err(SnapshotError::HeaderHistory);
        }
        let mut anchor_frontiers = Vec::with_capacity(frontier_count);
        for _ in 0..frontier_count {
            let height =
                u32::from_le_bytes(r.take_array().map_err(|_| SnapshotError::HeaderHistory)?);
            let frontier_len = usize::try_from(u32::from_le_bytes(
                r.take_array().map_err(|_| SnapshotError::HeaderHistory)?,
            ))
            .map_err(|_| SnapshotError::PayloadLength)?;
            let frontier = r
                .take(frontier_len)
                .map_err(|_| SnapshotError::HeaderHistory)?
                .to_vec();
            anchor_frontiers.push(SnapshotFrontier {
                height,
                bytes: frontier,
            });
        }
        let nullifier_count = usize::try_from(u64::from_le_bytes(
            r.take_array().map_err(|_| SnapshotError::PayloadLength)?,
        ))
        .map_err(|_| SnapshotError::PayloadLength)?;
        if u64::try_from(nullifier_count).ok() != Some(manifest.roots.nullifier_count)
            || nullifier_count.checked_mul(32) != Some(r.remaining())
        {
            return Err(SnapshotError::NullifierSet);
        }
        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            let encoded = r.take_array().map_err(|_| SnapshotError::PayloadLength)?;
            nullifiers
                .push(Nullifier::from_bytes(&encoded).map_err(|_| SnapshotError::NullifierSet)?);
        }
        r.finish().map_err(|_| SnapshotError::PayloadLength)?;
        Ok(Self {
            manifest,
            header_frontier,
            recent_headers,
            anchor_frontiers,
            nullifiers,
        })
    }
}

/// Checks snapshot metadata against the exact locally configured checkpoint.
/// The checkpoint is the trust anchor for header/work history; payload roots
/// are separately recomputed before installation.
pub fn verify_checkpoint_binding(
    params: &ChainParams,
    expected_chain_id: &[u8; 32],
    expected_rules_digest: &[u8; 32],
    checkpoint_header: &BlockHeader,
    checkpoint_work: ChainWork,
    manifest: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    let checkpoint = params
        .checkpoint_at(manifest.height)
        .ok_or(SnapshotError::NoCheckpoint)?;
    let header = checkpoint_header;
    let legacy_genesis = header.height == 0;
    let roots_match = header.height == manifest.height
        && header.hash() == manifest.block_hash
        && header.commitment_root == manifest.roots.commitment_root
        && (legacy_genesis || header.nullifier_root == manifest.roots.nullifier_root)
        && header.state_root == manifest.roots.state_root;
    if checkpoint.hash != manifest.block_hash
        || checkpoint.work != checkpoint_work
        || checkpoint.state_root != manifest.roots.state_root
        || manifest.chain_id != *expected_chain_id
        || header.hash() != checkpoint.hash
        || !roots_match
        || checkpoint_work.to_be_bytes() != manifest.chainwork
        || manifest.rules_digest != *expected_rules_digest
    {
        return Err(SnapshotError::CheckpointMismatch);
    }
    if manifest.encoding_version != SNAPSHOT_ENCODING_VERSION {
        return Err(SnapshotError::EncodingVersion);
    }
    Ok(())
}

/// Checks a snapshot's checkpoint binding and recomputes all payload roots.
/// The terminal header and cumulative work must match the exact configured
/// checkpoint, which is the trust anchor for the snapshot's old history.
pub fn verify_snapshot(
    params: &ChainParams,
    expected_rules_digest: &[u8; 32],
    chain_id: &[u8; 32],
    checkpoint_header: &BlockHeader,
    checkpoint_work: ChainWork,
    payload: &SnapshotPayload,
) -> Result<(), SnapshotError> {
    verify_checkpoint_binding(
        params,
        chain_id,
        expected_rules_digest,
        checkpoint_header,
        checkpoint_work,
        &payload.manifest,
    )?;
    verify_payload(payload, chain_id)?;
    let required_history = required_history_len(params, payload.manifest.height);
    if payload.recent_headers.len() != required_history
        || payload.anchor_frontiers.len() != required_history
    {
        return Err(SnapshotError::HeaderHistory);
    }
    Ok(())
}

fn required_history_len(params: &ChainParams, height: u32) -> usize {
    let retained = crate::validate::frontier_retention(params)
        .max(u32::try_from(crate::validate::header_lookback(params)).unwrap_or(u32::MAX));
    usize::try_from(height.min(retained).saturating_add(1)).unwrap_or(usize::MAX)
}

/// Checks payload encoding, counts and roots after checkpoint binding.
///
/// The sparse nullifier root is recomputed by the storage tree implementation;
/// this function does not infer payload integrity from the manifest alone.
pub fn verify_payload(payload: &SnapshotPayload, chain_id: &[u8; 32]) -> Result<(), SnapshotError> {
    if payload.manifest.encoding_version != SNAPSHOT_ENCODING_VERSION {
        return Err(SnapshotError::EncodingVersion);
    }
    let encoded_len = encoded_payload_len(
        &payload.header_frontier,
        &payload.recent_headers,
        &payload.anchor_frontiers,
        &payload.nullifiers,
    )
    .ok_or(SnapshotError::PayloadLength)?;
    let nullifier_count =
        u64::try_from(payload.nullifiers.len()).map_err(|_| SnapshotError::PayloadLength)?;
    if payload.manifest.chain_id != *chain_id
        || u64::try_from(encoded_len).ok() != Some(payload.manifest.payload_len)
    {
        return Err(SnapshotError::PayloadLength);
    }
    if nullifier_count != payload.manifest.roots.nullifier_count {
        return Err(SnapshotError::NullifierSet);
    }
    if payload.nullifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::NullifierSet);
    }
    let root = storage::nullifier::root_from_set(chain_id, &payload.nullifiers)
        .map_err(|_| SnapshotError::NullifierSet)?;
    if root != payload.manifest.roots.nullifier_root {
        return Err(SnapshotError::NullifierSet);
    }
    let legacy_genesis = payload.manifest.height == 0;
    let state_root = if legacy_genesis {
        Anchor::from_base(crypto::pallas::Base::from(0u64))
    } else {
        crate::state::state_root(
            chain_id,
            payload.manifest.height,
            payload.manifest.roots.commitment_root,
            payload.manifest.roots.commitment_count,
            payload.manifest.roots.nullifier_root,
            payload.manifest.roots.nullifier_count,
        )
    };
    if state_root != payload.manifest.roots.state_root {
        return Err(SnapshotError::CheckpointMismatch);
    }
    let Some(last) = payload.recent_headers.last() else {
        return Err(SnapshotError::HeaderHistory);
    };
    if payload.recent_headers.len() != payload.anchor_frontiers.len()
        || last.header.height != payload.manifest.height
        || last.header.hash() != payload.manifest.block_hash
        || last.header.commitment_root != payload.manifest.roots.commitment_root
        || (!legacy_genesis && last.header.nullifier_root != payload.manifest.roots.nullifier_root)
        || last.header.state_root != payload.manifest.roots.state_root
        || last.commitment_count != payload.manifest.roots.commitment_count
        || last.nullifier_count != payload.manifest.roots.nullifier_count
        || last.chainwork != payload.manifest.chainwork
    {
        return Err(SnapshotError::HeaderHistory);
    }
    let first = payload
        .recent_headers
        .first()
        .ok_or(SnapshotError::HeaderHistory)?;
    let mut history = payload.header_frontier.clone();
    if history.count() != u64::from(first.header.height)
        || history.tip_hash().unwrap_or(BlockHash::ZERO) != first.header.prev_hash
    {
        return Err(SnapshotError::HeaderHistory);
    }
    for (index, (entry, frontier)) in payload
        .recent_headers
        .iter()
        .zip(&payload.anchor_frontiers)
        .enumerate()
    {
        if entry.header.height != frontier.height {
            return Err(SnapshotError::HeaderHistory);
        }
        if let Some(previous) = index
            .checked_sub(1)
            .and_then(|i| payload.recent_headers.get(i))
        {
            if entry.header.height != previous.header.height.saturating_add(1)
                || entry.header.prev_hash != previous.header.hash()
            {
                return Err(SnapshotError::HeaderHistory);
            }
            let parent_work = ChainWork::from_be_bytes(previous.chainwork);
            let block_work = crate::target::Target::from_compact(entry.header.target)
                .and_then(|target| target.work())
                .map_err(|_| SnapshotError::HeaderHistory)?;
            let expected_work = parent_work
                .checked_add(block_work)
                .map_err(|_| SnapshotError::HeaderHistory)?;
            if expected_work.to_be_bytes() != entry.chainwork {
                return Err(SnapshotError::HeaderHistory);
            }
        }
        let tree = storage::tree::CommitmentTree::from_slice(&frontier.bytes)
            .map_err(|_| SnapshotError::CommitmentTree)?;
        if tree.root() != entry.header.commitment_root || tree.size() != entry.commitment_count {
            return Err(SnapshotError::CommitmentTree);
        }
        if entry.header.version == protocol::consensus::BLOCK_VERSION {
            if entry.header.history_root != history.root() {
                return Err(SnapshotError::HeaderHistory);
            }
            if entry.header.height == 0 {
                if entry.nullifier_count != 0
                    || entry.commitment_count != 0
                    || entry.header.nullifier_root
                        != Anchor::from_base(crypto::pallas::Base::from(0))
                    || entry.header.state_root != Anchor::from_base(crypto::pallas::Base::from(0))
                {
                    return Err(SnapshotError::HeaderHistory);
                }
            } else {
                let expected_state_root = crate::state::state_root(
                    chain_id,
                    entry.header.height,
                    tree.root(),
                    tree.size(),
                    entry.header.nullifier_root,
                    entry.nullifier_count,
                );
                if expected_state_root != entry.header.state_root {
                    return Err(SnapshotError::CheckpointMismatch);
                }
            }
        } else {
            return Err(SnapshotError::HeaderHistory);
        }
        history
            .append(&entry.header)
            .map_err(|_| SnapshotError::HeaderHistory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crypto::pallas;
    use protocol::block::empty_header;
    use protocol::nullifier::Nullifier;
    use storage::tree::CommitmentTree;

    use super::*;
    use crate::params::Checkpoint;

    fn anchor(value: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(value))
    }

    fn payload() -> SnapshotPayload {
        payload_at_height(5)
    }

    fn payload_at_height(tip_height: u32) -> SnapshotPayload {
        let tree = CommitmentTree::empty();
        let genesis_header = empty_header(0, BlockHash::ZERO, tree.root());
        let chain_id = *genesis_header.hash().as_bytes();
        let nullifiers = vec![
            Nullifier::from_base(&pallas::Base::from(3)),
            Nullifier::from_base(&pallas::Base::from(7)),
        ];
        let nullifier_root = storage::nullifier::root_from_set(&chain_id, &nullifiers).unwrap();
        let state_root = crate::state::state_root(
            &chain_id,
            tip_height,
            tree.root(),
            tree.size(),
            nullifier_root,
            nullifiers.len() as u64,
        );
        let roots = SnapshotRoots {
            commitment_root: tree.root(),
            commitment_count: tree.size(),
            nullifier_root,
            nullifier_count: nullifiers.len() as u64,
            state_root,
        };
        let mut recent_headers = Vec::new();
        let mut anchor_frontiers = Vec::new();
        let mut prev_hash = BlockHash::ZERO;
        let target = ChainParams::test().pow_limit.to_compact();
        let mut cumulative_work = ChainWork::ZERO;
        let header_frontier = HeaderFrontier::empty();
        let mut history = header_frontier.clone();
        for height in 0..=tip_height {
            let mut header = empty_header(height, prev_hash, tree.root());
            if height > 0 {
                header.target = target;
                cumulative_work = cumulative_work
                    .checked_add(
                        crate::target::Target::from_compact(target)
                            .unwrap()
                            .work()
                            .unwrap(),
                    )
                    .unwrap();
            }
            let nf_count = if height == 0 {
                0
            } else {
                nullifiers.len() as u64
            };
            if height > 0 {
                header.history_root = history.root();
                header.body_root = protocol::body_tree::body_root(&[]).unwrap();
                header.nullifier_root = nullifier_root;
                header.state_root = crate::state::state_root(
                    &chain_id,
                    height,
                    tree.root(),
                    tree.size(),
                    nullifier_root,
                    nf_count,
                );
            }
            history.append(&header).unwrap();
            prev_hash = header.hash();
            recent_headers.push(SnapshotHeaderState {
                header,
                commitment_count: tree.size(),
                nullifier_count: nf_count,
                chainwork: cumulative_work.to_be_bytes(),
            });
            anchor_frontiers.push(SnapshotFrontier {
                height,
                bytes: tree.to_vec(),
            });
        }
        let block_hash = recent_headers.last().unwrap().header.hash();
        let manifest = SnapshotManifest::for_payload(
            chain_id,
            [4; 32],
            tip_height,
            block_hash,
            cumulative_work,
            roots,
            &header_frontier,
            &recent_headers,
            &anchor_frontiers,
            &nullifiers,
        )
        .unwrap();
        SnapshotPayload {
            manifest,
            header_frontier,
            recent_headers,
            anchor_frontiers,
            nullifiers,
        }
    }

    #[test]
    fn manifest_roundtrip_and_payload_roots_are_checked() {
        let payload = payload();
        let manifest = SnapshotManifest::from_bytes(&payload.manifest.to_bytes()).unwrap();
        assert_eq!(manifest, payload.manifest);
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(
            SnapshotPayload::from_bytes(manifest.clone(), &bytes, 4096).unwrap(),
            payload
        );
        assert_eq!(
            SnapshotPayload::from_bytes(manifest.clone(), &bytes, 1),
            Err(SnapshotError::PayloadLength)
        );
        verify_payload(&payload, &payload.manifest.chain_id).unwrap();
        verify_snapshot(
            &ChainParams::mainnet(),
            &payload.manifest.rules_digest,
            &payload.manifest.chain_id,
            &payload.recent_headers.last().unwrap().header,
            ChainWork::from_be_bytes(payload.manifest.chainwork),
            &payload,
        )
        .unwrap_err(); // There is no configured checkpoint in this network profile.

        let mut wrong_root = payload.clone();
        wrong_root.manifest.roots.nullifier_root = anchor(99);
        assert_eq!(
            verify_payload(&wrong_root, &payload.manifest.chain_id),
            Err(SnapshotError::NullifierSet)
        );

        let mut wrong_state_root = payload.clone();
        wrong_state_root.manifest.roots.state_root = anchor(100);
        assert_eq!(
            verify_payload(&wrong_state_root, &payload.manifest.chain_id),
            Err(SnapshotError::CheckpointMismatch)
        );

        let mut wrong_count = payload.clone();
        wrong_count.nullifiers.pop();
        assert_eq!(
            verify_payload(&wrong_count, &payload.manifest.chain_id),
            Err(SnapshotError::PayloadLength)
        );
    }

    #[test]
    fn malformed_or_noncanonical_payload_is_rejected() {
        let payload = payload();
        let mut trailing = payload.to_bytes().unwrap();
        trailing.push(0);
        assert_eq!(
            SnapshotPayload::from_bytes(payload.manifest.clone(), &trailing, 4096),
            Err(SnapshotError::PayloadLength)
        );

        let mut duplicate = payload.clone();
        duplicate.nullifiers[1] = duplicate.nullifiers[0];
        assert_eq!(
            verify_payload(&duplicate, &payload.manifest.chain_id),
            Err(SnapshotError::NullifierSet)
        );
    }

    #[test]
    fn opaque_header_prefix_is_bound_to_the_retained_suffix() {
        let mut payload = payload();
        let prefix_headers: Vec<_> = payload.recent_headers.drain(..3).collect();
        payload.anchor_frontiers.drain(..3);
        for entry in prefix_headers {
            payload.header_frontier.append(&entry.header).unwrap();
        }
        payload.manifest = SnapshotManifest::for_payload(
            payload.manifest.chain_id,
            payload.manifest.rules_digest,
            payload.manifest.height,
            payload.manifest.block_hash,
            ChainWork::from_be_bytes(payload.manifest.chainwork),
            payload.manifest.roots,
            &payload.header_frontier,
            &payload.recent_headers,
            &payload.anchor_frontiers,
            &payload.nullifiers,
        )
        .unwrap();
        verify_payload(&payload, &payload.manifest.chain_id).unwrap();
        let encoded = payload.to_bytes().unwrap();
        assert_eq!(
            SnapshotPayload::from_bytes(payload.manifest.clone(), &encoded, 4096).unwrap(),
            payload
        );
        let mut wrong_prefix = payload.clone();
        wrong_prefix.header_frontier = HeaderFrontier::empty();
        wrong_prefix.manifest.payload_len = u64::try_from(
            encoded_payload_len(
                &wrong_prefix.header_frontier,
                &wrong_prefix.recent_headers,
                &wrong_prefix.anchor_frontiers,
                &wrong_prefix.nullifiers,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_payload(&wrong_prefix, &payload.manifest.chain_id),
            Err(SnapshotError::HeaderHistory)
        );
    }

    #[test]
    fn checkpoint_snapshot_with_opaque_prefix_can_be_installed_and_exported_again() {
        let mut payload = payload_at_height(17);
        let prefix_headers: Vec<_> = payload.recent_headers.drain(..6).collect();
        payload.anchor_frontiers.drain(..6);
        for entry in prefix_headers {
            payload.header_frontier.append(&entry.header).unwrap();
        }
        payload.manifest = SnapshotManifest::for_payload(
            payload.manifest.chain_id,
            payload.manifest.rules_digest,
            payload.manifest.height,
            payload.manifest.block_hash,
            ChainWork::from_be_bytes(payload.manifest.chainwork),
            payload.manifest.roots,
            &payload.header_frontier,
            &payload.recent_headers,
            &payload.anchor_frontiers,
            &payload.nullifiers,
        )
        .unwrap();
        let mut params = ChainParams {
            max_reorg_depth: 0,
            anchor_max_age: 0,
            difficulty_window: 0,
            ..ChainParams::test()
        };
        let tip_header = &payload.recent_headers.last().unwrap().header;
        let checkpoint = Checkpoint {
            height: tip_header.height,
            hash: tip_header.hash(),
            work: ChainWork::from_be_bytes(payload.manifest.chainwork),
            state_root: tip_header.state_root,
        };
        params.checkpoints = Box::leak(Box::new([checkpoint]));
        verify_snapshot(
            &params,
            &payload.manifest.rules_digest,
            &payload.manifest.chain_id,
            tip_header,
            checkpoint.work,
            &payload,
        )
        .unwrap();

        let directory = tempfile::tempdir().unwrap();
        let store = storage::store::Store::open(directory.path().join("snapshot.redb")).unwrap();
        store
            .install_snapshot(
                &payload.to_storage_install().unwrap(),
                storage::store::SnapshotInstallMode::EmptyOnly,
            )
            .unwrap();
        assert!(store.header(&tip_header.prev_hash).unwrap().is_some());
        assert!(store
            .header(&payload.recent_headers[0].header.prev_hash)
            .unwrap()
            .is_none());
        let exported = SnapshotPayload::from_store_at(
            &store,
            &params,
            &payload.manifest.chain_id,
            checkpoint.height,
        )
        .unwrap();
        assert_eq!(exported, payload);

        // Opaque old mountains support future appends, but do not invent
        // membership paths for headers whose internal nodes were not shipped.
        assert!(store.header_path(&checkpoint.hash, 0).unwrap().is_none());
        let recent_header = &payload.recent_headers[payload.recent_headers.len() - 2].header;
        let path = store
            .header_path(&checkpoint.hash, recent_header.height)
            .unwrap()
            .unwrap();
        assert!(path.verify(recent_header, &tip_header.history_root));
    }

    #[test]
    fn oversized_header_frontier_is_rejected_before_parsing() {
        let payload = payload();
        let mut encoded = payload.to_bytes().unwrap();
        encoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            SnapshotPayload::from_bytes(payload.manifest, &encoded, 4096),
            Err(SnapshotError::HeaderHistory)
        );
    }

    #[test]
    fn snapshot_requires_an_exact_configured_checkpoint() {
        let params = ChainParams::mainnet();
        let payload = payload();
        let header = payload.recent_headers.last().unwrap().header.clone();
        assert_eq!(
            verify_checkpoint_binding(
                &params,
                &payload.manifest.chain_id,
                &payload.manifest.rules_digest,
                &header,
                ChainWork::ZERO,
                &payload.manifest,
            ),
            Err(SnapshotError::NoCheckpoint)
        );
    }

    #[test]
    fn configured_checkpoint_binds_header_rules_roots_and_work() {
        let mut params = ChainParams::mainnet();
        let payload = payload();
        let header = payload.recent_headers.last().unwrap().header.clone();
        let checkpoint = Checkpoint {
            height: header.height,
            hash: header.hash(),
            work: ChainWork::from_u256(crate::target::U256::from_big_endian(
                &payload.manifest.chainwork,
            )),
            state_root: header.state_root,
        };
        params.checkpoints = Box::leak(vec![checkpoint].into_boxed_slice());
        let manifest = payload.manifest.clone();
        let checkpoint_work = ChainWork::from_be_bytes(manifest.chainwork);
        assert_eq!(
            verify_checkpoint_binding(
                &params,
                &payload.manifest.chain_id,
                &manifest.rules_digest,
                &header,
                checkpoint_work,
                &manifest,
            ),
            Ok(())
        );
        assert_eq!(
            verify_checkpoint_binding(
                &params,
                &payload.manifest.chain_id,
                &[8; 32],
                &header,
                checkpoint_work,
                &manifest,
            ),
            Err(SnapshotError::CheckpointMismatch)
        );
        assert_eq!(
            verify_checkpoint_binding(
                &params,
                &payload.manifest.chain_id,
                &manifest.rules_digest,
                &header,
                ChainWork::from_u256(crate::target::U256::one()),
                &manifest,
            ),
            Err(SnapshotError::CheckpointMismatch)
        );
        assert_eq!(
            verify_snapshot(
                &params,
                &manifest.rules_digest,
                &payload.manifest.chain_id,
                &header,
                checkpoint_work,
                &payload,
            ),
            Ok(())
        );
        assert_eq!(
            verify_snapshot(
                &params,
                &manifest.rules_digest,
                &[8; 32],
                &header,
                checkpoint_work,
                &payload,
            ),
            Err(SnapshotError::CheckpointMismatch)
        );
    }
}
