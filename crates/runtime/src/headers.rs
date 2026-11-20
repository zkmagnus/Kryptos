//! Header validation before any body download or chainwork policy decision.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use chain::chain::Chain;
use chain::target::ChainWork;
use chain::validate::{branch_headers, header_lookback, Validator};
use protocol::block::{header_len_for_version, BlockHeader};
use protocol::bytes::Encodable;
use protocol::header_tree::HeaderFrontier;

use crate::Result;

/// Bounded ancestry and validated cumulative work for one sync candidate.
#[derive(Default)]
pub(crate) struct SyncHeaders {
    recent: Vec<BlockHeader>,
    work: Option<ChainWork>,
    /// Header-tree frontier through the last verified candidate header.
    header_frontier: Option<HeaderFrontier>,
    /// Headers below this fixed release checkpoint are only hash-linked so
    /// far: their calculated work must not authorize body downloads yet.
    pending_checkpoint: Option<chain::params::Checkpoint>,
    /// Validated bodies may wait for arbitrarily much minimum chainwork.
    /// Keep their small headers in a private temporary file, not growing RAM.
    deferred: Option<File>,
    read_offset: u64,
    write_offset: u64,
}

impl SyncHeaders {
    /// The anonymous file is created inside the node's private data directory
    /// and removed automatically when this candidate is dropped or aborted.
    pub(crate) fn new(datadir: &Path) -> Result<Self> {
        Ok(Self {
            deferred: Some(tempfile::tempfile_in(datadir)?),
            ..Self::default()
        })
    }

    /// Appends headers only after verification and `BlockSync` solicitation checks.
    /// This permits long below-threshold chains without unbounded memory or
    /// prematurely downloading their bodies. Before a trusted checkpoint,
    /// fixed checkpoint height bounds the pending prefix. Beyond it, each
    /// additional header must pay verified proof of work, never claimed nBits.
    pub(crate) fn defer(&mut self, headers: &[BlockHeader]) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }
        let file = self
            .deferred
            .as_mut()
            .ok_or_else(|| std::io::Error::other("header spool not initialized"))?;
        file.seek(SeekFrom::Start(self.write_offset))?;
        let mut next_offset = self.write_offset;
        for header in headers {
            let bytes = header.to_vec();
            file.write_all(&bytes)?;
            next_offset = next_offset
                .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| std::io::Error::other("header spool offset overflow"))?;
        }
        self.write_offset = next_offset;
        Ok(())
    }

    /// Whether every accepted header has proof of work or a completed hash
    /// chain to the trusted checkpoint. A claimed partial prefix cannot admit
    /// bodies or complete initial synchronization, regardless of its work.
    pub(crate) fn authenticated(&self) -> bool {
        self.pending_checkpoint.is_none()
    }

    /// Whether validated headers still await body admission.
    pub(crate) fn has_deferred(&self) -> bool {
        self.read_offset < self.write_offset
    }

    /// Reads one bounded chunk, oldest first, once the total work is sufficient.
    pub(crate) fn take_deferred(&mut self, limit: usize) -> Result<Vec<BlockHeader>> {
        if !self.authenticated() {
            return Err(p2p::Error::BadHeaders("checkpoint prefix not authenticated").into());
        }
        if !self.has_deferred() || limit == 0 {
            return Ok(Vec::new());
        }
        let file = self
            .deferred
            .as_mut()
            .ok_or_else(|| std::io::Error::other("header spool not initialized"))?;
        file.seek(SeekFrom::Start(self.read_offset))?;
        let mut next_offset = self.read_offset;
        let mut headers = Vec::new();
        while next_offset < self.write_offset && headers.len() < limit {
            let mut version = [0u8; 1];
            file.read_exact(&mut version)?;
            let len = header_len_for_version(version[0])
                .ok_or(p2p::Error::BadHeaders("unknown header version"))?;
            let mut bytes = vec![0; len];
            bytes[0] = version[0];
            file.read_exact(
                bytes
                    .get_mut(1..)
                    .ok_or_else(|| std::io::Error::other("invalid header length"))?,
            )?;
            headers.push(BlockHeader::from_slice(&bytes)?);
            next_offset = next_offset
                .checked_add(u64::try_from(len).unwrap_or(u64::MAX))
                .ok_or_else(|| std::io::Error::other("header spool offset overflow"))?;
        }
        self.read_offset = next_offset;
        if self.read_offset == self.write_offset {
            file.set_len(0)?;
            self.read_offset = 0;
            self.write_offset = 0;
        }
        Ok(headers)
    }

    /// Validates a whole response before advancing the candidate. The rolling
    /// ancestry suffices for difficulty and median-time rules across batches.
    pub(crate) fn verify(
        &mut self,
        chain: &Chain,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<ChainWork> {
        let Some(first) = headers.first() else {
            return self
                .work
                .map_or_else(|| chain.tip_chainwork().map_err(Into::into), Ok);
        };
        if headers.len() > p2p::message::MAX_HEADERS {
            return Err(p2p::Error::BadHeaders("too many headers").into());
        }
        let params = chain.params();
        let lookback = header_lookback(params);
        let (mut recent, mut work, mut history) = if let Some(work) = self.work {
            (
                self.recent.clone(),
                work,
                self.header_frontier
                    .clone()
                    .ok_or(chain::Error::InvalidHeader(
                        "candidate header frontier missing",
                    ))?,
            )
        } else {
            let parent = chain
                .store()
                .header(&first.prev_hash)?
                .ok_or(chain::Error::Orphan)?;
            (
                branch_headers(chain.store(), &parent, lookback)?,
                chain.chainwork(&first.prev_hash)?,
                chain.store().header_frontier(&first.prev_hash)?.ok_or(
                    chain::Error::InvalidHeader("parent header frontier missing"),
                )?,
            )
        };
        let mut pending_checkpoint = self.pending_checkpoint;
        if self.work.is_none() {
            // The checkpoint height bounds the unauthenticated prefix. It is
            // fixed in a release, not supplied by a peer. A stored parent was
            // already validated; later unknown headers only become authenticated
            // once their links reach this exact configured hash.
            pending_checkpoint = params
                .checkpoints
                .iter()
                .rev()
                .find(|checkpoint| checkpoint.height >= first.height)
                .copied();
        }
        let checkpoint_height = pending_checkpoint.map(|checkpoint| checkpoint.height);
        let mut parent = recent.last().ok_or(chain::Error::Orphan)?;
        for header in headers {
            if header.prev_hash != parent.hash()
                || parent.height.checked_add(1) != Some(header.height)
            {
                return Err(chain::Error::InvalidHeader("header chain gap").into());
            }
            if let Some(checkpoint) = params.checkpoint_at(header.height) {
                if header.hash() != checkpoint.hash || header.state_root != checkpoint.state_root {
                    return Err(chain::Error::InvalidHeader("conflicts with a checkpoint").into());
                }
            }
            if pending_checkpoint.is_some_and(|checkpoint| checkpoint.height == header.height) {
                pending_checkpoint = None;
            }
            parent = header;
        }
        let validator = Validator {
            params,
            pow: chain.pow(),
            vk: chain.verifying_key(),
            chain_id: chain.chain_id(),
            now,
        };
        for header in headers {
            let target = validator.check_header_rules(header, &recent)?;
            if history.count() != u64::from(header.height)
                || history.tip_hash() != Some(header.prev_hash)
                || header.history_root != history.root()
            {
                return Err(chain::Error::InvalidHeader("header history root mismatch").into());
            }
            history.append(header)?;
            if checkpoint_height.is_none_or(|height| header.height > height) {
                chain.pow().check(header)?;
            }
            work = work.checked_add(target.work()?)?;
            if let Some(checkpoint) = params.checkpoint_at(header.height) {
                if work != checkpoint.work {
                    return Err(chain::Error::InvalidHeader("conflicts with a checkpoint").into());
                }
            }
            recent.push(header.clone());
            if recent.len() > lookback {
                recent.remove(0);
            }
        }
        self.recent = recent;
        self.work = Some(work);
        self.header_frontier = Some(history);
        self.pending_checkpoint = pending_checkpoint;
        Ok(work)
    }
}

#[cfg(test)]
mod tests {
    use chain::genesis::genesis;
    use chain::params::{ChainParams, Checkpoint};
    use chain::target::Target;
    use protocol::block::empty_header;
    use protocol::transaction::Anchor;
    use storage::store::Store;
    use transaction_proof::VerifyingKey;

    use super::*;

    fn child(
        parent: &BlockHeader,
        params: &ChainParams,
        history: &mut HeaderFrontier,
    ) -> BlockHeader {
        history.append(parent).unwrap();
        let mut header = empty_header(
            parent.height.saturating_add(1),
            parent.hash(),
            parent.commitment_root,
        );
        header.timestamp = parent.timestamp.saturating_add(params.block_interval);
        header.target = params.pow_limit.to_compact();
        header.history_root = history.root();
        header
    }

    fn expected_work(params: &ChainParams, height: u32) -> ChainWork {
        (0..height).fold(ChainWork::ZERO, |work, _| {
            work.checked_add(params.pow_limit.work().unwrap()).unwrap()
        })
    }

    fn make_chain(dir: &std::path::Path, params: ChainParams) -> Chain {
        Chain::new(
            Store::open(dir.join("chain.redb")).unwrap(),
            params,
            VerifyingKey::build().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn wrong_difficulty_is_rejected_even_when_anchored_at_a_checkpoint() {
        let mut params = ChainParams::test();
        let genesis = genesis(&params);
        let mut history = HeaderFrontier::empty();
        let mut header = child(genesis.header(), &params, &mut history);
        header.target = Target::from_compact(0x200f_ffff).unwrap().to_compact();
        params.checkpoints = Box::leak(Box::new([Checkpoint {
            height: 1,
            hash: header.hash(),
            work: expected_work(&params, 1),
            state_root: Anchor::from_base(crypto::pallas::Base::zero()),
        }]));
        let dir = tempfile::tempdir().unwrap();
        let chain = make_chain(dir.path(), params);
        let mut state = SyncHeaders::default();
        assert!(matches!(
            state.verify(&chain, &[header], u64::MAX),
            Err(crate::Error::Chain(chain::Error::InvalidHeader(
                "target does not match the difficulty rule"
            )))
        ));
        assert!(state.work.is_none());
        assert_eq!(state.recent, [] as [BlockHeader; 0]);
    }

    #[test]
    fn checkpoint_cannot_authorize_an_inconsistent_header_history_root() {
        let mut params = ChainParams::test();
        let genesis = genesis(&params);
        let mut history = HeaderFrontier::empty();
        let mut header = child(genesis.header(), &params, &mut history);
        header.history_root[0] ^= 1;
        params.checkpoints = Box::leak(Box::new([Checkpoint {
            height: 1,
            hash: header.hash(),
            work: expected_work(&params, 1),
            state_root: header.state_root,
        }]));
        let dir = tempfile::tempdir().unwrap();
        let chain = make_chain(dir.path(), params);
        let mut state = SyncHeaders::default();
        assert!(matches!(
            state.verify(&chain, &[header], u64::MAX),
            Err(crate::Error::Chain(chain::Error::InvalidHeader(
                "header history root mismatch"
            )))
        ));
        assert!(state.work.is_none());
        assert!(state.header_frontier.is_none());
        assert!(state.recent.is_empty());
    }

    #[test]
    fn checkpoint_authenticates_ancestry_but_rejected_batch_cannot_advance_state() {
        let mut params = ChainParams::test();
        let genesis = genesis(&params);
        let mut history = HeaderFrontier::empty();
        let first = child(genesis.header(), &params, &mut history);
        let second = child(&first, &params, &mut history);
        params.checkpoints = Box::leak(Box::new([Checkpoint {
            height: 2,
            hash: second.hash(),
            work: expected_work(&params, 2),
            state_root: Anchor::from_base(crypto::pallas::Base::zero()),
        }]));
        let dir = tempfile::tempdir().unwrap();
        let chain = make_chain(dir.path(), params);
        // No RandomX solutions: linkage to the exact trusted checkpoint is
        // sufficient; difficulty is still checked for every header.
        assert!(chain.pow().check(&first).is_err());
        let mut state = SyncHeaders::default();
        let mut conflicting = second.clone();
        conflicting.nonce[0] = 1;
        assert!(state
            .verify(&chain, &[first.clone(), conflicting], u64::MAX)
            .is_err());
        assert!(state.work.is_none());
        assert_eq!(state.recent, [] as [BlockHeader; 0]);
        let work = state
            .verify(&chain, &[first, second.clone()], u64::MAX)
            .unwrap();
        let single = params.pow_limit.work().unwrap();
        assert_eq!(work, single.checked_add(single).unwrap());
        assert_eq!(state.recent.last(), Some(&second));
        let frontier = state.header_frontier.as_ref().unwrap();
        assert_eq!(frontier.count(), 3);
        assert_eq!(frontier.tip_hash(), Some(second.hash()));
        assert_eq!(state.verify(&chain, &[], u64::MAX).unwrap(), work);
    }

    #[test]
    fn verified_ancestry_and_work_continue_across_responses() {
        let mut params = ChainParams::test();
        let genesis = genesis(&params);
        let mut history = HeaderFrontier::empty();
        let first = child(genesis.header(), &params, &mut history);
        let second = child(&first, &params, &mut history);
        let third = child(&second, &params, &mut history);
        let fourth = child(&third, &params, &mut history);
        params.checkpoints = Box::leak(Box::new([
            Checkpoint {
                height: 2,
                hash: second.hash(),
                work: expected_work(&params, 2),
                state_root: Anchor::from_base(crypto::pallas::Base::zero()),
            },
            Checkpoint {
                height: 4,
                hash: fourth.hash(),
                work: expected_work(&params, 4),
                state_root: Anchor::from_base(crypto::pallas::Base::zero()),
            },
        ]));
        let dir = tempfile::tempdir().unwrap();
        let chain = make_chain(dir.path(), params);
        let mut state = SyncHeaders::default();
        let first_work = state
            .verify(&chain, &[first.clone(), second], u64::MAX)
            .unwrap();
        assert!(
            !state.authenticated(),
            "prefix has not reached the final checkpoint"
        );
        // Replayed headers cannot count twice or replace the verified ancestry.
        assert!(state.verify(&chain, &[first], u64::MAX).is_err());
        assert_eq!(state.work, Some(first_work));
        let second_work = state
            .verify(&chain, &[third, fourth.clone()], u64::MAX)
            .unwrap();
        assert_eq!(second_work, first_work.checked_add(first_work).unwrap());
        assert_eq!(state.recent.last(), Some(&fourth));
        assert!(state.authenticated());
    }

    #[test]
    fn deferred_headers_exceed_memory_window_and_drain_in_order() {
        let params = ChainParams::test();
        let mut parent = genesis(&params).header().clone();
        let mut history = HeaderFrontier::empty();
        let mut all = Vec::new();
        let count = p2p::sync::MAX_QUEUED_HEADERS.saturating_add(10);
        for _ in 0..count {
            parent = child(&parent, &params, &mut history);
            all.push(parent.clone());
        }
        let dir = tempfile::tempdir().unwrap();
        let mut state = SyncHeaders::new(dir.path()).unwrap();
        for batch in all.chunks(p2p::message::MAX_HEADERS) {
            state.defer(batch).unwrap();
        }
        assert!(state.has_deferred());
        let mut read = Vec::new();
        while state.has_deferred() {
            let batch = state.take_deferred(17).unwrap();
            assert!(batch.len() <= 17);
            read.extend(batch);
        }
        assert_eq!(all, read);
        assert_eq!(
            state.deferred.as_ref().unwrap().metadata().unwrap().len(),
            0
        );
        assert_eq!(state.take_deferred(10).unwrap(), [] as [BlockHeader; 0]);
        // The same file can spool the next batch after being drained.
        state.defer(&all[..3]).unwrap();
        assert_eq!(state.take_deferred(10).unwrap(), all[..3]);
    }

    #[test]
    fn incomplete_checkpoint_prefix_never_becomes_authenticated() {
        let mut params = ChainParams::test();
        let genesis = genesis(&params);
        let mut history = HeaderFrontier::empty();
        let first = child(genesis.header(), &params, &mut history);
        let second = child(&first, &params, &mut history);
        params.checkpoints = Box::leak(Box::new([Checkpoint {
            height: 2,
            hash: second.hash(),
            work: expected_work(&params, 2),
            state_root: Anchor::from_base(crypto::pallas::Base::zero()),
        }]));
        let dir = tempfile::tempdir().unwrap();
        let chain = make_chain(dir.path(), params);
        let mut state = SyncHeaders::default();
        state.verify(&chain, &[first], u64::MAX).unwrap();
        assert!(!state.authenticated());
        state.verify(&chain, &[], u64::MAX).unwrap();
        assert!(
            !state.authenticated(),
            "short response does not authenticate a prefix"
        );
        let mut conflict = second.clone();
        conflict.nonce[0] = 1;
        assert!(state.verify(&chain, &[conflict], u64::MAX).is_err());
        assert!(!state.authenticated());
        state.verify(&chain, &[second], u64::MAX).unwrap();
        assert!(state.authenticated());
    }
}
