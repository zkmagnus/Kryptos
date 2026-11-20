//! Bounded disk quarantine for complete bodies fetched after their headers.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use protocol::block::{Block, BlockHash, BlockHeader};
use protocol::bytes::Encodable;

use crate::{Error, Result};

/// Maximum bytes staged plus held by a validation worker.
pub(crate) const MAX_STAGED_BYTES: usize = 2 * p2p::message::MAX_MESSAGE_LEN;

/// Result of trying to add one already-decoded P2P block body.
pub(crate) enum Insert {
    /// The body was written to its private anonymous file.
    Added,
    /// The same block hash is already queued.
    Duplicate,
    /// The entry or byte bound is full; the body is returned for retry.
    Full(Box<Block>),
}

pub(crate) struct DownloadedBodies {
    datadir: PathBuf,
    entries: HashMap<BlockHash, DownloadedBody>,
    bytes: Arc<AtomicUsize>,
    count: Arc<AtomicUsize>,
}

pub(crate) struct DownloadedBody {
    pub from: u64,
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub received: Instant,
    file: File,
    len: usize,
    bytes: Arc<AtomicUsize>,
    count: Arc<AtomicUsize>,
}

impl DownloadedBodies {
    pub fn new(datadir: PathBuf) -> Self {
        Self {
            datadir,
            entries: HashMap::new(),
            bytes: Arc::new(AtomicUsize::new(0)),
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Whether a body is still staged in the map. Active worker leases remain
    /// accounted against the global byte and entry limits until dropped.
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Whether there are no staged bodies or active worker leases.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.count.load(Ordering::Relaxed) == 0
    }

    /// Total staged plus active bytes.
    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Staged plus active entry count.
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Stores the exact canonical block bytes without validating authorization
    /// or changing chain state.
    pub fn insert(&mut self, from: u64, block: Block) -> Result<Insert> {
        let hash = block.hash();
        if self.entries.contains_key(&hash) {
            return Ok(Insert::Duplicate);
        }

        let encoded_len = encoded_len(&block)?;
        if encoded_len > p2p::message::MAX_MESSAGE_LEN || !reserve_count(&self.count) {
            return Ok(Insert::Full(Box::new(block)));
        }
        if !reserve_bytes(&self.bytes, encoded_len) {
            self.count.fetch_sub(1, Ordering::Relaxed);
            return Ok(Insert::Full(Box::new(block)));
        }

        let result = (|| {
            let mut file = tempfile::tempfile_in(&self.datadir)?;
            let bytes = block.to_vec();
            if bytes.len() != encoded_len {
                return Err(Error::Argument("block encoding length changed".into()));
            }
            file.write_all(&bytes)?;
            Ok(DownloadedBody {
                from,
                hash,
                header: block.header().clone(),
                received: Instant::now(),
                file,
                len: encoded_len,
                bytes: Arc::clone(&self.bytes),
                count: Arc::clone(&self.count),
            })
        })();

        match result {
            Ok(body) => {
                self.entries.insert(hash, body);
                Ok(Insert::Added)
            }
            Err(error) => {
                self.bytes.fetch_sub(encoded_len, Ordering::Relaxed);
                self.count.fetch_sub(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    /// Takes the lowest-height body whose parent is already stored, preserving
    /// parent-first validation while allowing download responses to arrive out
    /// of order. The returned file keeps its quota lease until it is dropped.
    pub fn take_ready(
        &mut self,
        mut parent_known: impl FnMut(&BlockHash) -> bool,
    ) -> Option<DownloadedBody> {
        let hash = self
            .entries
            .values()
            .filter(|entry| parent_known(&entry.header.prev_hash))
            .min_by_key(|entry| (entry.header.height, entry.hash))
            .map(|entry| entry.hash)?;
        self.entries.remove(&hash)
    }

    /// Drops the highest staged body strictly above an incoming parent's
    /// height. The caller can requeue that peer/hash after making room for
    /// the earlier dependency; an active worker lease is never evicted.
    pub fn evict_above(&mut self, height: u32) -> Option<(u64, BlockHash)> {
        let hash = self
            .entries
            .values()
            .filter(|entry| entry.header.height > height)
            .max_by_key(|entry| (entry.header.height, entry.hash))
            .map(|entry| entry.hash)?;
        let body = self.entries.remove(&hash)?;
        let source = (body.from, body.hash);
        drop(body);
        Some(source)
    }

    /// Removes staged files. Active worker leases stay charged until their
    /// owners drop them.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl DownloadedBody {
    /// Reads, decodes, and checks the staged body against the header captured
    /// on receipt. The file and quota lease remain held so the caller can
    /// retain them until consensus authorization finishes.
    pub fn read(&mut self) -> Result<Block> {
        self.file.seek(SeekFrom::Start(0))?;
        let limit = u64::try_from(self.len)
            .unwrap_or(u64::MAX)
            .checked_add(1)
            .ok_or_else(|| Error::Argument("staged body length overflow".into()))?;
        let mut bytes = Vec::with_capacity(self.len);
        Read::by_ref(&mut self.file)
            .take(limit)
            .read_to_end(&mut bytes)?;
        if bytes.len() != self.len {
            return Err(Error::Argument("staged body file length changed".into()));
        }
        let block = Block::from_slice(&bytes)?;
        if block.header() != &self.header || block.hash() != self.hash {
            return Err(Error::Argument("staged body header changed".into()));
        }
        Ok(block)
    }
}

impl Drop for DownloadedBody {
    fn drop(&mut self) {
        self.bytes.fetch_sub(self.len, Ordering::Relaxed);
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve_count(count: &AtomicUsize) -> bool {
    reserve(count, 1, p2p::sync::MAX_IN_FLIGHT)
}

fn reserve_bytes(bytes: &AtomicUsize, size: usize) -> bool {
    reserve(bytes, size, MAX_STAGED_BYTES)
}

fn reserve(counter: &AtomicUsize, amount: usize, maximum: usize) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > maximum {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn encoded_len(block: &Block) -> Result<usize> {
    if block.transactions().len() > protocol::consensus::MAX_BLOCK_TRANSACTIONS {
        return Err(Error::Argument("too many staged block transactions".into()));
    }
    block.transactions().iter().try_fold(
        block
            .header()
            .encoded_len()
            .checked_add(core::mem::size_of::<u32>())
            .ok_or_else(|| Error::Argument("block encoding length overflow".into()))?,
        |len, transaction| {
            if transaction.proof().as_bytes().len()
                != protocol::consensus::proof_len(transaction.actions().len())?
            {
                return Err(Error::Argument(
                    "staged transaction proof encoding length".into(),
                ));
            }
            len.checked_add(protocol::transaction::Transaction::encoded_len_for_actions(
                transaction.actions().len(),
            )?)
            .ok_or_else(|| Error::Argument("block encoding length overflow".into()))
        },
    )
}

#[cfg(test)]
mod tests {
    use protocol::block::empty_header;
    use protocol::transaction::Anchor;

    use super::*;

    fn empty_block(height: u32, parent: BlockHash) -> Block {
        Block::new(
            empty_header(
                height,
                parent,
                Anchor::from_base(crypto::pallas::Base::from(0u64)),
            ),
            Vec::new(),
        )
    }

    #[test]
    fn bodies_roundtrip_and_duplicates_do_not_consume_quota() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        let block = empty_block(1, BlockHash::from_bytes([7; 32]));
        let expected_len = block.to_vec().len();
        assert!(matches!(
            bodies.insert(4, block.clone()).unwrap(),
            Insert::Added
        ));
        assert!(matches!(
            bodies.insert(9, block.clone()).unwrap(),
            Insert::Duplicate
        ));
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies.bytes(), expected_len);
        assert!(bodies.contains(&block.hash()));
        assert!(bodies.take_ready(|_| false).is_none());
        let mut downloaded = bodies.take_ready(|_| true).unwrap();
        assert_eq!(downloaded.from, 4);
        assert_eq!(downloaded.hash, block.hash());
        assert_eq!(downloaded.header, *block.header());
        assert!(downloaded.received <= Instant::now());
        assert_eq!(downloaded.read().unwrap(), block);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies.bytes(), expected_len);
        drop(downloaded);
        assert!(bodies.is_empty());
        assert_eq!(bodies.bytes(), 0);
    }

    #[test]
    fn ready_bodies_are_taken_parent_first_despite_response_order() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        let genesis = empty_block(0, BlockHash::ZERO);
        let first = empty_block(1, genesis.hash());
        let second = empty_block(2, first.hash());
        bodies.insert(7, second.clone()).unwrap();
        bodies.insert(8, first.clone()).unwrap();
        let mut next = bodies
            .take_ready(|parent| *parent == genesis.hash())
            .unwrap();
        assert_eq!(next.read().unwrap(), first);
        assert!(bodies
            .take_ready(|parent| *parent == genesis.hash())
            .is_none());
        assert_eq!(
            bodies
                .take_ready(|parent| *parent == first.hash())
                .unwrap()
                .read()
                .unwrap(),
            second
        );
    }

    #[test]
    fn clear_drops_queued_files_but_preserves_an_active_quota_lease() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        let first = empty_block(1, BlockHash::ZERO);
        let second = empty_block(2, first.hash());
        bodies.insert(1, first.clone()).unwrap();
        bodies.insert(2, second).unwrap();
        let active = bodies.take_ready(|_| true).unwrap();
        bodies.clear();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies.bytes(), first.to_vec().len());
        assert!(!bodies.is_empty());
        drop(active);
        assert!(bodies.is_empty());
        assert_eq!(bodies.bytes(), 0);
    }

    #[test]
    fn entry_capacity_counts_an_active_file_and_recovers_after_clear() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        for height in 1..=p2p::sync::MAX_IN_FLIGHT {
            let block = empty_block(u32::try_from(height).unwrap(), BlockHash::ZERO);
            assert!(matches!(bodies.insert(1, block).unwrap(), Insert::Added));
        }
        let active = bodies.take_ready(|_| true).unwrap();
        let another = empty_block(99, BlockHash::ZERO);
        assert!(matches!(
            bodies.insert(1, another.clone()).unwrap(),
            Insert::Full(_)
        ));
        bodies.clear();
        assert_eq!(bodies.len(), 1);
        drop(active);
        assert!(matches!(bodies.insert(1, another).unwrap(), Insert::Added));
    }

    #[test]
    fn descending_responses_cannot_keep_the_needed_parent_out_of_a_full_spool() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        let mut highest = None;
        for height in (2..=p2p::sync::MAX_IN_FLIGHT + 1).rev() {
            let height = u32::try_from(height).unwrap();
            let block = empty_block(height, BlockHash::ZERO);
            if highest.is_none() {
                highest = Some((u64::from(height), block.hash()));
            }
            assert!(matches!(
                bodies.insert(u64::from(height), block).unwrap(),
                Insert::Added
            ));
        }
        let parent = empty_block(1, BlockHash::ZERO);
        let retained_parent = match bodies.insert(1, parent.clone()).unwrap() {
            Insert::Full(block) => block,
            _ => panic!("full spool must return the needed parent for retry"),
        };
        assert_eq!(bodies.evict_above(1), highest);
        assert_eq!(bodies.len(), p2p::sync::MAX_IN_FLIGHT - 1);
        assert!(matches!(
            bodies.insert(1, *retained_parent).unwrap(),
            Insert::Added
        ));
        assert_eq!(bodies.len(), p2p::sync::MAX_IN_FLIGHT);
        assert!(bodies.contains(&parent.hash()));
        assert!(bodies.evict_above(u32::MAX).is_none());
        assert_eq!(bodies.take_ready(|_| true).unwrap().read().unwrap(), parent);
    }

    #[test]
    fn corrupt_files_fail_before_validation_and_release_their_quota() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().to_path_buf());
        let block = empty_block(1, BlockHash::ZERO);
        bodies.insert(1, block.clone()).unwrap();
        let mut downloaded = bodies.take_ready(|_| true).unwrap();
        downloaded
            .file
            .set_len(u64::try_from(downloaded.len + 1).unwrap())
            .unwrap();
        assert!(downloaded.read().is_err());
        drop(downloaded);
        assert!(bodies.is_empty());

        bodies.insert(1, block).unwrap();
        let mut downloaded = bodies.take_ready(|_| true).unwrap();
        let replacement = empty_block(2, BlockHash::ZERO).to_vec();
        assert_eq!(replacement.len(), downloaded.len);
        downloaded.file.seek(SeekFrom::Start(0)).unwrap();
        downloaded.file.write_all(&replacement).unwrap();
        assert!(downloaded.read().is_err());
        drop(downloaded);
        assert!(bodies.is_empty());
    }

    #[test]
    fn local_io_failure_and_byte_limit_do_not_leak_reservations() {
        let directory = tempfile::tempdir().unwrap();
        let mut bodies = DownloadedBodies::new(directory.path().join("absent"));
        assert!(bodies.insert(1, empty_block(1, BlockHash::ZERO)).is_err());
        assert!(bodies.is_empty());
        assert_eq!(bodies.bytes(), 0);
        let bytes = AtomicUsize::new(MAX_STAGED_BYTES - 3);
        assert!(!reserve_bytes(&bytes, 4));
        assert!(reserve_bytes(&bytes, 3));
        assert_eq!(bytes.load(Ordering::Relaxed), MAX_STAGED_BYTES);
    }
}
