//! Headers-first synchronization: build a locator, accept a chained run
//! of headers, then download the bodies in order with bounded in-flight
//! requests and timeouts.
//!
//! Headers are requested one message at a time and only while the queue
//! of headers awaiting download is below a low-water mark, so the queue
//! never exceeds [`MAX_QUEUED_HEADERS`] however long the peer's chain is.

use std::collections::{HashMap, VecDeque};

use chain::target::ChainWork;
use protocol::block::{BlockHash, BlockHeader};

use crate::message::{MAX_HEADERS, MAX_LOCATOR};
use crate::{Error, Result};

/// Block requests kept in flight at once.
pub const MAX_IN_FLIGHT: usize = 16;
/// Bodies requested from one onion stream at a time.
pub const MAX_IN_FLIGHT_PER_PEER: usize = 2;
/// Local download and initial-sync policy, deliberately outside consensus.
/// Increase alongside release checkpoints once the network has known work.
pub const MIN_CHAIN_WORK: ChainWork = ChainWork::ZERO;
/// Seconds before an unanswered block request is retried.
pub const REQUEST_TIMEOUT: u64 = 300;
/// More headers are requested only while fewer than this are queued.
pub const HEADERS_LOW_WATER: usize = 2 * MAX_HEADERS;
/// Most headers awaiting download at once: the low-water mark plus one
/// full message. Solicitation and message-size limits enforce this bound.
pub const MAX_QUEUED_HEADERS: usize = HEADERS_LOW_WATER + MAX_HEADERS;

/// Hashes from the tip backwards: the last ten densely, then doubling
/// steps, ending with genesis, so a peer on any fork finds a common point.
pub fn locator(tip_height: u32, hash_at: impl Fn(u32) -> Option<BlockHash>) -> Vec<BlockHash> {
    let mut hashes = Vec::new();
    let mut height = tip_height;
    let mut step = 1u32;
    loop {
        if let Some(hash) = hash_at(height) {
            hashes.push(hash);
        }
        if height == 0 || hashes.len() >= MAX_LOCATOR.saturating_sub(1) {
            break;
        }
        if hashes.len() >= 10 {
            step = step.saturating_mul(2);
        }
        height = height.saturating_sub(step);
    }
    if height != 0 {
        if let Some(genesis) = hash_at(0) {
            hashes.push(genesis);
        }
    }
    hashes
}

/// Progress reported after a headers message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Headers queued for download.
    pub queued: usize,
    /// Whether the peer sent fewer than the maximum, meaning it has no more.
    pub exhausted: bool,
}

#[derive(Debug)]
struct Request {
    header: BlockHeader,
    peer: u64,
    generation: u64,
    /// No response deadline until the stream writer completes the request.
    sent: Option<u64>,
}

/// Download state.
#[derive(Debug)]
pub struct BlockSync {
    queue: VecDeque<BlockHeader>,
    in_flight: HashMap<BlockHash, Request>,
    last_header: Option<BlockHeader>,
    /// A headers request has been sent and not yet answered.
    headers_outstanding: Option<u64>,
    /// A reserved headers request, not yet acknowledged by the stream writer.
    headers_pending: bool,
    /// Request identifiers distinguish retries even for the same peer/hash.
    request_generation: u64,
    headers_generation: u64,
    request_timeout: u64,
    /// Cumulative work of the last header, calculated by the validator.
    chainwork: Option<ChainWork>,
    /// Greater of the local tip work and this release's download threshold.
    required_work: ChainWork,
    /// The peer has sent a short headers message: it has no more.
    exhausted: bool,
}

impl Default for BlockSync {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSync {
    /// A syncer whose first headers request, built from a locator by the
    /// caller, is reserved. Call [`Self::headers_sent_for_request`] after writing it.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            in_flight: HashMap::new(),
            last_header: None,
            headers_outstanding: None,
            headers_pending: true,
            request_generation: 1,
            headers_generation: 1,
            request_timeout: REQUEST_TIMEOUT,
            chainwork: None,
            required_work: MIN_CHAIN_WORK,
            exhausted: false,
        }
    }

    /// A sync candidate using the configured response timeout for both
    /// header and body requests, starting only when their writes complete.
    pub fn with_timeout(seconds: u64) -> Self {
        Self {
            request_timeout: seconds.max(1),
            ..Self::new()
        }
    }

    /// Whether a reserved or written headers request may receive a response.
    /// Check before expensive header verification to reject unsolicited work.
    pub fn expects_headers(&self) -> bool {
        self.headers_pending || self.headers_outstanding.is_some()
    }

    /// Whether the peer has sent everything it has.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Whether nothing is queued or in flight.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.in_flight.is_empty()
    }

    /// Headers queued but not yet requested.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Removes only the newly queued headers reported by [`Progress::queued`]
    /// for the caller's disk spool. Earlier queued or reassigned bodies stay
    /// ahead of unread spool entries when more headers arrive.
    pub fn take_received_headers(&mut self, count: usize) -> Vec<BlockHeader> {
        self.queue
            .split_off(self.queue.len().saturating_sub(count))
            .into_iter()
            .collect()
    }

    /// Restores the oldest verified headers from the caller's spool, after
    /// its cumulative work has met policy. This is not a network entry point.
    ///
    /// # Errors
    /// Refuses admission before sufficient work or beyond the memory bound.
    pub fn queue_headers(&mut self, headers: &[BlockHeader]) -> Result<()> {
        if !self.meets_required_work() {
            return Err(Error::BadHeaders("insufficient chain work"));
        }
        if self
            .queue
            .len()
            .saturating_add(self.in_flight.len())
            .saturating_add(headers.len())
            > MAX_QUEUED_HEADERS
        {
            return Err(Error::BadHeaders("header spool batch exceeds capacity"));
        }
        self.queue.extend(headers.iter().cloned());
        Ok(())
    }

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The last header accepted, the point to build the next locator from.
    pub fn last_header(&self) -> Option<&BlockHeader> {
        self.last_header.as_ref()
    }

    /// Cumulative work of the last validated header, if any.
    pub fn chainwork(&self) -> Option<ChainWork> {
        self.chainwork
    }

    /// Refreshes the local work threshold before scheduling more bodies.
    /// The local tip may have advanced while a candidate was being scanned.
    pub fn set_required_work(&mut self, required: ChainWork) {
        self.required_work = required.max(MIN_CHAIN_WORK);
    }

    /// Whether the validated headers meet the local download policy.
    /// This never changes block validity.
    pub fn meets_required_work(&self) -> bool {
        self.chainwork
            .is_some_and(|work| work >= self.required_work)
    }

    /// Whether policy prevents downloads and the peer has exhausted its
    /// headers or reached the bounded queue limit. Release this candidate
    /// rather than let it
    /// hold initial synchronization open indefinitely.
    pub fn work_blocked(&self) -> bool {
        !self.meets_required_work() && (self.exhausted || self.queue.len() >= HEADERS_LOW_WATER)
    }

    /// Accepts a requested headers message. The caller must first validate
    /// difficulty, proof of work (or the hash chain to a trusted checkpoint),
    /// and cumulative work against the known parent. `chainwork` is that
    /// validated total; `required_work` is the greater of local tip work and
    /// [`MIN_CHAIN_WORK`]. An insufficient total queues headers but never
    /// permits body requests. `known` says whether we already
    /// have a block, so its body can be skipped. The first response starts
    /// at a known parent; every subsequent header must directly extend the
    /// last accepted header, even when both blocks are already known.
    ///
    /// # Errors
    /// Returns [`Error::BadHeaders`] on an unsolicited response, a gap,
    /// an out-of-order header, or an oversized headers message.
    /// A rejected response leaves the download state unchanged.
    pub fn on_headers(
        &mut self,
        headers: &[BlockHeader],
        known: impl Fn(&BlockHash) -> bool,
        chainwork: ChainWork,
        required_work: ChainWork,
    ) -> Result<Progress> {
        if !self.expects_headers() {
            return Err(Error::BadHeaders("unsolicited headers"));
        }
        if headers.len() > MAX_HEADERS {
            return Err(Error::BadHeaders("too many headers"));
        }
        let mut pending = Vec::new();
        let mut last = self.last_header.as_ref();
        for header in headers {
            let hash = header.hash();
            let chains = match last {
                Some(parent) => {
                    parent.hash() == header.prev_hash
                        && parent.height.checked_add(1) == Some(header.height)
                }
                None => known(&header.prev_hash),
            };
            if !chains {
                return Err(Error::BadHeaders("gap"));
            }
            last = Some(header);
            if !known(&hash) {
                pending.push(header.clone());
            }
        }
        let queued = pending.len();
        self.queue.extend(pending);
        if let Some(header) = headers.last() {
            self.last_header = Some(header.clone());
        }
        self.headers_outstanding = None;
        self.headers_pending = false;
        if !headers.is_empty() || self.chainwork.is_none() {
            self.chainwork = Some(chainwork);
        }
        self.required_work = required_work.max(MIN_CHAIN_WORK);
        self.exhausted = headers.len() < MAX_HEADERS;
        Ok(Progress {
            queued,
            exhausted: self.exhausted,
        })
    }

    /// The header to continue from if more headers should be requested
    /// now: the peer has more, no request is outstanding, and the queue
    /// is below the low-water mark. Reserves the request; its timeout begins
    /// only when [`Self::headers_sent_for_request`] records the completed write.
    pub fn next_headers_request(&mut self) -> Option<BlockHash> {
        if self.exhausted
            || self.headers_pending
            || self.headers_outstanding.is_some()
            || self.queue.len().saturating_add(self.in_flight.len()) >= HEADERS_LOW_WATER
        {
            return None;
        }
        let from = self.last_header.as_ref()?.hash();
        self.request_generation = self.request_generation.checked_add(1)?;
        self.headers_generation = self.request_generation;
        self.headers_pending = true;
        Some(from)
    }

    /// Starts the headers deadline after the request has reached the stream.
    /// The caller must deliver write notifications before processing the
    /// corresponding response; no notification changes an answered request.
    fn headers_sent(&mut self, now: u64) {
        if self.headers_pending {
            self.headers_pending = false;
            self.headers_outstanding = Some(now);
        }
    }

    /// Identifier to attach to a queued headers write. The runtime also binds
    /// it to the current sync session so old-session writes are discarded.
    pub fn header_request_id(&self) -> Option<u64> {
        self.expects_headers().then_some(self.headers_generation)
    }

    /// Starts only this request's deadline, ignoring stale write callbacks.
    pub fn headers_sent_for_request(&mut self, request_id: u64, now: u64) {
        if request_id == self.headers_generation {
            self.headers_sent(now);
        }
    }

    /// Whether the last written headers request has missed its deadline.
    pub fn headers_timed_out(&self, now: u64) -> bool {
        self.headers_outstanding
            .is_some_and(|sent| now.saturating_sub(sent) >= self.request_timeout)
    }

    /// Reserves body requests for `peer`, bounded globally and per stream.
    /// No deadline starts until [`Self::requests_sent_for_requests`] confirms the write.
    pub fn next_requests_for(&mut self, peer: u64) -> Vec<BlockHash> {
        if !self.meets_required_work() {
            return Vec::new();
        }
        let available = MAX_IN_FLIGHT_PER_PEER.saturating_sub(
            self.in_flight
                .values()
                .filter(|request| request.peer == peer)
                .count(),
        );
        let mut requests = Vec::new();
        while requests.len() < available && self.in_flight.len() < MAX_IN_FLIGHT {
            let Some(generation) = self.request_generation.checked_add(1) else {
                break;
            };
            let Some(header) = self.queue.pop_front() else {
                break;
            };
            self.request_generation = generation;
            let hash = header.hash();
            self.in_flight.insert(
                hash,
                Request {
                    header,
                    peer,
                    generation,
                    sent: None,
                },
            );
            requests.push(hash);
        }
        requests
    }

    /// Identifier to attach to a queued body request, including retries.
    pub fn body_request_id(&self, hash: &BlockHash) -> Option<u64> {
        self.in_flight.get(hash).map(|request| request.generation)
    }

    /// Records completed writes only when their reservation is still current.
    /// Session identifiers are checked by the caller before entering this state.
    pub fn requests_sent_for_requests(
        &mut self,
        peer: u64,
        requests: &[(BlockHash, u64)],
        now: u64,
    ) {
        for (hash, generation) in requests {
            if let Some(request) = self.in_flight.get_mut(hash) {
                if request.peer == peer
                    && request.generation == *generation
                    && request.sent.is_none()
                {
                    request.sent = Some(now);
                }
            }
        }
    }

    /// Whether this block is still awaiting successful import.
    pub fn expects(&self, hash: &BlockHash) -> bool {
        self.in_flight.contains_key(hash)
    }

    /// The peer responsible for a reserved or written body request.
    pub fn owner(&self, hash: &BlockHash) -> Option<u64> {
        self.in_flight.get(hash).map(|request| request.peer)
    }

    /// Clears an unresolved body's deadline and invalidates its old write ticket.
    /// Use when a response awaits its parent, and again when requesting it after
    /// that parent arrives. The new deadline starts only when
    /// [`Self::requests_sent_for_requests`] confirms the new write.
    pub fn retry(&mut self, hash: &BlockHash) -> bool {
        let Some(generation) = self.request_generation.checked_add(1) else {
            return false;
        };
        let Some(request) = self.in_flight.get_mut(hash) else {
            return false;
        };
        self.request_generation = generation;
        request.generation = generation;
        request.sent = None;
        true
    }

    /// Returns a missing body to the queue only if this peer owns its request.
    /// The caller excludes that peer before rescheduling to prevent retry loops.
    pub fn request_failed(&mut self, peer: u64, hash: &BlockHash) -> bool {
        if self.owner(hash) != Some(peer) {
            return false;
        }
        let Some(request) = self.in_flight.remove(hash) else {
            return false;
        };
        let position = self
            .queue
            .iter()
            .position(|header| header.height > request.header.height)
            .unwrap_or(self.queue.len());
        self.queue.insert(position, request.header);
        true
    }

    /// Returns disconnected peers' reservations to the queue, parents first.
    /// Other peers can immediately fill their existing fixed-size windows.
    pub fn peer_disconnected(&mut self, peer: u64) {
        let mut returned = Vec::new();
        self.in_flight.retain(|_, request| {
            if request.peer == peer {
                returned.push(request.header.clone());
                false
            } else {
                true
            }
        });
        returned.extend(self.queue.drain(..));
        returned.sort_by_key(|header| header.height);
        self.queue.extend(returned);
    }

    /// Acknowledges a successfully imported block; returns whether it was
    /// expected. Receipt alone must not remove an unresolved dependency.
    pub fn on_block(&mut self, hash: &BlockHash) -> bool {
        self.in_flight.remove(hash).is_some()
    }

    /// Requeues written requests that exceeded their deadline, returning each
    /// block and the peer that owned it. The caller excludes those peers before
    /// rescheduling. Unsent reservations never expire.
    pub fn timeouts(&mut self, now: u64) -> Vec<(BlockHash, u64)> {
        let mut expired: Vec<_> = self
            .in_flight
            .iter()
            .filter(|(_, request)| {
                request
                    .sent
                    .is_some_and(|sent| now.saturating_sub(sent) >= self.request_timeout)
            })
            .map(|(hash, request)| (*hash, request.peer))
            .collect();
        expired.sort_unstable();
        for (hash, peer) in &expired {
            self.request_failed(*peer, hash);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use crypto::pallas;
    use protocol::block::empty_header;
    use protocol::transaction::Anchor;

    use super::*;

    impl BlockSync {
        fn requests_sent(&mut self, peer: u64, hashes: &[BlockHash], now: u64) {
            let tickets: Vec<_> = hashes
                .iter()
                .filter_map(|hash| self.body_request_id(hash).map(|ticket| (*hash, ticket)))
                .collect();
            self.requests_sent_for_requests(peer, &tickets, now);
        }
    }

    fn next_requests(sync: &mut BlockSync, now: u64) -> Vec<BlockHash> {
        let mut requests = Vec::new();
        for peer in 0..8 {
            let batch = sync.next_requests_for(peer);
            sync.requests_sent(peer, &batch, now);
            requests.extend(batch);
        }
        requests
    }

    fn chain(len: u32) -> Vec<BlockHeader> {
        let mut out: Vec<BlockHeader> = Vec::new();
        for height in 0..len {
            let prev = out.last().map_or(BlockHash::ZERO, BlockHeader::hash);
            out.push(empty_header(
                height,
                prev,
                Anchor::from_base(pallas::Base::from(u64::from(height))),
            ));
        }
        out
    }

    #[test]
    fn locator_is_dense_then_sparse_and_ends_at_genesis() {
        let headers = chain(100);
        let hashes: Vec<BlockHash> = headers.iter().map(BlockHeader::hash).collect();
        let loc = locator(99, |h| hashes.get(h as usize).copied());
        assert_eq!(loc[0], hashes[99]);
        assert_eq!(loc[9], hashes[90]);
        assert_eq!(loc[10], hashes[88]);
        assert_eq!(loc[11], hashes[84]);
        assert_eq!(*loc.last().unwrap(), hashes[0]);
        assert!(loc.len() <= MAX_LOCATOR);
        assert_eq!(
            locator(0, |h| hashes.get(h as usize).copied()),
            vec![hashes[0]]
        );
    }

    #[test]
    fn headers_chain_are_queued_and_downloaded_in_order() {
        let headers = chain(5);
        let genesis = headers[0].hash();
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(
                &headers[1..],
                |h| *h == genesis,
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(
            progress,
            Progress {
                queued: 4,
                exhausted: true
            }
        );
        assert_eq!(sync.last_header().unwrap().height, 4);
        let requests = next_requests(&mut sync, 0);
        assert_eq!(
            requests,
            headers[1..]
                .iter()
                .map(BlockHeader::hash)
                .collect::<Vec<_>>()
        );
        assert!(!sync.on_block(&BlockHash::ZERO));
        for hash in &requests {
            assert!(sync.on_block(hash));
        }
        assert!(sync.is_idle());
    }

    #[test]
    fn known_headers_are_skipped_and_gaps_are_rejected() {
        let headers = chain(5);
        let known = [headers[0].hash(), headers[1].hash()];
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(
                &headers[1..],
                |h| known.contains(h),
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(progress.queued, 3);
        let mut bad = BlockSync::new();
        assert!(matches!(
            bad.on_headers(
                &headers[2..],
                |h| *h == headers[0].hash(),
                ChainWork::ZERO,
                MIN_CHAIN_WORK
            ),
            Err(Error::BadHeaders(_))
        ));
    }

    #[test]
    fn header_requests_pause_at_the_low_water_mark_and_resume_as_blocks_arrive() {
        let headers = chain(u32::try_from(HEADERS_LOW_WATER + 1).unwrap());
        let mut sync = BlockSync::new();
        assert_eq!(
            sync.next_headers_request(),
            None,
            "the first request is outstanding"
        );
        sync.on_headers(
            &headers[1..=MAX_HEADERS],
            |h| *h == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        assert!(!sync.exhausted());
        let from = sync.next_headers_request().unwrap();
        assert_eq!(from, headers[MAX_HEADERS].hash());
        assert_eq!(sync.next_headers_request(), None, "one at a time");

        sync.on_headers(
            &headers[MAX_HEADERS + 1..],
            |_| false,
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);
        assert_eq!(sync.next_headers_request(), None, "queue at the mark");

        let requested = next_requests(&mut sync, 0);
        for hash in &requested {
            sync.on_block(hash);
        }
        assert!(sync.next_headers_request().is_some(), "queue drained");
    }

    #[test]
    fn unsolicited_headers_cannot_overfill_queue_and_exhaustion_stops_requests() {
        let headers = chain(u32::try_from(MAX_QUEUED_HEADERS + 2).unwrap());
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..=MAX_HEADERS],
            |h| *h == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        assert!(sync.next_headers_request().is_some());
        sync.on_headers(
            &headers[MAX_HEADERS + 1..=HEADERS_LOW_WATER],
            |_| false,
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);
        assert_eq!(sync.next_headers_request(), None);
        assert!(matches!(
            sync.on_headers(
                &headers[HEADERS_LOW_WATER + 1..=MAX_QUEUED_HEADERS],
                |_| { false },
                ChainWork::ZERO,
                MIN_CHAIN_WORK
            ),
            Err(Error::BadHeaders("unsolicited headers"))
        ));
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);

        let mut short = BlockSync::new();
        short
            .on_headers(
                &headers[1..3],
                |h| *h == headers[0].hash(),
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert!(short.exhausted());
        assert_eq!(short.next_headers_request(), None);
    }

    #[test]
    fn repeated_known_headers_are_rejected_without_advancing_state() {
        let headers = chain(3);
        let repeated = vec![headers[1].clone(); MAX_HEADERS];
        let mut sync = BlockSync::new();
        assert!(matches!(
            sync.on_headers(&repeated, |_| true, ChainWork::ZERO, MIN_CHAIN_WORK),
            Err(Error::BadHeaders("gap"))
        ));
        assert!(sync.is_idle());
        assert!(!sync.exhausted());
        assert!(sync.last_header().is_none());
        // Rejection preserves the outstanding request, so an honest response
        // can still fulfill it instead of being treated as unsolicited.
        let progress = sync
            .on_headers(
                &headers[1..],
                |hash| *hash == headers[0].hash(),
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(progress.queued, 2);
    }

    #[test]
    fn known_parents_do_not_allow_gaps_or_partial_queue_updates() {
        let headers = chain(5);
        let mut sync = BlockSync::new();
        let disordered = [headers[1].clone(), headers[3].clone()];
        assert!(matches!(
            sync.on_headers(
                &disordered,
                |hash| { *hash == headers[0].hash() || *hash == headers[2].hash() },
                ChainWork::ZERO,
                MIN_CHAIN_WORK
            ),
            Err(Error::BadHeaders("gap"))
        ));
        // The first unknown header must not have leaked into the queue.
        assert!(sync.is_idle());
        assert!(sync.last_header().is_none());
        assert!(!sync.exhausted());
        let progress = sync
            .on_headers(
                &headers[1..],
                |hash| *hash == headers[0].hash(),
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(progress.queued, 4);
    }

    #[test]
    fn continuation_must_extend_requested_hash_even_when_replayed_blocks_are_known() {
        let headers = chain(u32::try_from(MAX_HEADERS + 3).unwrap());
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(
                &headers[1..=MAX_HEADERS],
                |_| true,
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(progress.queued, 0);
        assert!(!progress.exhausted);
        assert_eq!(
            sync.next_headers_request(),
            Some(headers[MAX_HEADERS].hash())
        );
        assert!(matches!(
            sync.on_headers(
                &headers[1..=MAX_HEADERS],
                |_| true,
                ChainWork::ZERO,
                MIN_CHAIN_WORK
            ),
            Err(Error::BadHeaders("gap"))
        ));
        assert_eq!(
            sync.last_header().unwrap().hash(),
            headers[MAX_HEADERS].hash()
        );
        assert!(!sync.exhausted());
        assert!(sync.is_idle());

        let progress = sync
            .on_headers(
                &headers[MAX_HEADERS + 1..],
                |_| false,
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        assert_eq!(progress.queued, 2);
        assert!(progress.exhausted);
        assert_eq!(sync.next_headers_request(), None);
    }

    #[test]
    fn response_size_and_solicitation_are_enforced_atomically() {
        let headers = chain(u32::try_from(MAX_HEADERS + 2).unwrap());
        let mut sync = BlockSync::new();
        assert!(matches!(
            sync.on_headers(&headers[1..], |_| true, ChainWork::ZERO, MIN_CHAIN_WORK),
            Err(Error::BadHeaders("too many headers"))
        ));
        assert!(sync.last_header().is_none());
        assert!(sync.is_idle());
        assert!(!sync.exhausted());
        sync.on_headers(
            &headers[1..=MAX_HEADERS],
            |_| true,
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        assert!(matches!(
            sync.on_headers(&[], |_| true, ChainWork::ZERO, MIN_CHAIN_WORK),
            Err(Error::BadHeaders("unsolicited headers"))
        ));
        assert!(!sync.exhausted());
        assert!(sync.next_headers_request().is_some());
        let done = sync
            .on_headers(&[], |_| true, ChainWork::ZERO, MIN_CHAIN_WORK)
            .unwrap();
        assert_eq!(done.queued, 0);
        assert!(done.exhausted);
        assert!(sync.is_idle());
        assert_eq!(
            sync.last_header().unwrap().height,
            u32::try_from(MAX_HEADERS).unwrap()
        );
    }

    #[test]
    fn in_flight_is_bounded_and_timeouts_requeue_requests() {
        let headers = chain(40);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |h| *h == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let first = next_requests(&mut sync, 0);
        assert_eq!(first.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.queued(), 39 - MAX_IN_FLIGHT);
        assert_eq!(next_requests(&mut sync, 1).len(), 0);
        assert_eq!(sync.timeouts(REQUEST_TIMEOUT - 1).len(), 0);
        let expired = sync.timeouts(REQUEST_TIMEOUT);
        assert_eq!(expired.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.in_flight(), 0);
        assert_eq!(sync.queued(), 39);
    }

    #[test]
    fn unresolved_bodies_remain_expected_and_retry_extends_the_deadline() {
        let headers = chain(3);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |hash| *hash == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        next_requests(&mut sync, 0);
        let parent = headers[1].hash();
        let child = headers[2].hash();
        assert!(sync.expects(&child));
        // An out-of-order child has not been successfully imported, so it
        // remains tracked while its parent is acknowledged.
        assert!(sync.on_block(&parent));
        assert!(!sync.expects(&parent));
        assert!(sync.expects(&child));
        assert!(!sync.is_idle());
        assert!(sync.retry(&child));
        assert!(!sync.retry(&parent));
        sync.requests_sent(sync.owner(&child).unwrap(), &[child], REQUEST_TIMEOUT - 1);
        assert_eq!(sync.timeouts(REQUEST_TIMEOUT), [] as [(BlockHash, u64); 0]);
        assert_eq!(sync.timeouts(2 * REQUEST_TIMEOUT - 1), vec![(child, 0)]);
        assert!(!sync.expects(&child));
        assert!(!sync.is_idle());
        assert_eq!(sync.next_requests_for(1), vec![child]);
    }

    #[test]
    fn insufficient_chainwork_never_requests_bodies() {
        use chain::target::U256;
        let headers = chain(3);
        let mut sync = BlockSync::new();
        let work = ChainWork::from_u256(U256::from(2));
        let minimum = ChainWork::from_u256(U256::from(3));
        sync.on_headers(&headers[1..], |h| *h == headers[0].hash(), work, minimum)
            .unwrap();
        assert!(!sync.meets_required_work());
        assert!(sync.work_blocked());
        assert_eq!(sync.next_requests_for(1), [] as [BlockHash; 0]);
        assert_eq!(sync.queued(), 2);
        assert_eq!(sync.in_flight(), 0);

        let mut equal = BlockSync::new();
        equal
            .on_headers(&headers[1..], |h| *h == headers[0].hash(), minimum, minimum)
            .unwrap();
        assert!(equal.meets_required_work());
        assert_eq!(equal.next_requests_for(1).len(), 2);
    }

    #[test]
    fn empty_response_retains_verified_work() {
        use chain::target::U256;
        let headers = chain(u32::try_from(MAX_HEADERS + 1).unwrap());
        let mut sync = BlockSync::new();
        let work = ChainWork::from_u256(U256::from(20));
        sync.on_headers(&headers[1..], |_| true, work, work)
            .unwrap();
        assert!(sync.next_headers_request().is_some());
        sync.on_headers(&[], |_| true, ChainWork::ZERO, work)
            .unwrap();
        assert_eq!(sync.chainwork(), Some(work));
        assert!(sync.meets_required_work());
    }

    #[test]
    fn header_deadline_starts_only_after_the_stream_write() {
        let mut sync = BlockSync::new();
        assert!(!sync.headers_timed_out(u64::MAX));
        sync.headers_sent(50);
        assert!(!sync.headers_timed_out(49));
        assert!(!sync.headers_timed_out(50 + REQUEST_TIMEOUT - 1));
        assert!(sync.headers_timed_out(50 + REQUEST_TIMEOUT));
        sync.on_headers(&[], |_| true, ChainWork::ZERO, MIN_CHAIN_WORK)
            .unwrap();
        assert!(!sync.headers_timed_out(u64::MAX));
        sync.headers_sent(70);
        assert!(
            !sync.headers_timed_out(u64::MAX),
            "late write acknowledgment"
        );
    }

    #[test]
    fn reservations_do_not_timeout_and_each_peer_has_a_small_window() {
        let headers = chain(12);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |h| *h == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let first = sync.next_requests_for(1);
        let second = sync.next_requests_for(2);
        assert_eq!(first.len(), MAX_IN_FLIGHT_PER_PEER);
        assert_eq!(second.len(), MAX_IN_FLIGHT_PER_PEER);
        assert_eq!(sync.next_requests_for(1), [] as [BlockHash; 0]);
        assert_eq!(sync.timeouts(u64::MAX), [] as [(BlockHash, u64); 0]);
        sync.requests_sent(9, &first, 0);
        assert!(sync.timeouts(u64::MAX).is_empty(), "wrong owner ignored");
        sync.requests_sent(1, &first, 100);
        sync.requests_sent(1, &first, 150);
        assert_eq!(
            sync.timeouts(100 + REQUEST_TIMEOUT - 1),
            [] as [(BlockHash, u64); 0]
        );
        let mut expired = sync.timeouts(100 + REQUEST_TIMEOUT);
        expired.sort_unstable();
        let mut expected: Vec<_> = first.into_iter().map(|hash| (hash, 1)).collect();
        expected.sort_unstable();
        assert_eq!(expired, expected, "duplicate ack did not extend deadline");
        assert_eq!(sync.in_flight(), second.len());
    }

    #[test]
    fn disconnected_peer_requests_are_reassigned_in_height_order() {
        let headers = chain(8);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |h| *h == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let first = sync.next_requests_for(1);
        let second = sync.next_requests_for(2);
        sync.peer_disconnected(1);
        assert_eq!(sync.next_requests_for(3), first);
        assert!(second.iter().all(|hash| sync.owner(hash) == Some(2)));
        assert!(first.iter().all(|hash| sync.owner(hash) == Some(3)));
        sync.requests_sent(1, &first, 0);
        assert_eq!(sync.timeouts(u64::MAX), [] as [(BlockHash, u64); 0]);
    }

    #[test]
    fn late_header_write_ack_cannot_start_the_next_requests_deadline() {
        let headers = chain(u32::try_from(MAX_HEADERS + 1).unwrap());
        let mut sync = BlockSync::new();
        let first = sync.header_request_id().unwrap();
        sync.on_headers(&headers[1..], |_| true, ChainWork::ZERO, MIN_CHAIN_WORK)
            .unwrap();
        assert!(sync.next_headers_request().is_some());
        let continuation = sync.header_request_id().unwrap();
        sync.headers_sent_for_request(first, 0);
        assert!(!sync.headers_timed_out(u64::MAX));
        sync.headers_sent_for_request(continuation, 100);
        assert!(!sync.headers_timed_out(100 + REQUEST_TIMEOUT - 1));
        assert!(sync.headers_timed_out(100 + REQUEST_TIMEOUT));
    }

    #[test]
    fn below_threshold_scan_can_spool_multiple_windows_before_body_admission() {
        use chain::target::U256;
        let count = MAX_HEADERS.saturating_mul(4);
        let headers = chain(u32::try_from(count.saturating_add(1)).unwrap());
        let required = ChainWork::from_u256(U256::from(count));
        let mut sync = BlockSync::new();
        let mut spool = Vec::new();
        for (index, batch) in headers[1..].chunks(MAX_HEADERS).enumerate() {
            let work = ChainWork::from_u256(U256::from((index + 1) * MAX_HEADERS));
            let progress = sync
                .on_headers(batch, |hash| *hash == headers[0].hash(), work, required)
                .unwrap();
            spool.extend(sync.take_received_headers(progress.queued));
            if work < required {
                assert_eq!(sync.next_requests_for(1), [] as [BlockHash; 0]);
                assert!(sync.queue_headers(&spool[..1]).is_err());
                assert!(sync.next_headers_request().is_some());
            }
        }
        assert!(sync.meets_required_work());
        assert!(spool.len() > MAX_QUEUED_HEADERS);
        assert!(sync.queue_headers(&spool).is_err());
        sync.queue_headers(&spool[..MAX_HEADERS]).unwrap();
        assert_eq!(
            sync.next_requests_for(1),
            vec![headers[1].hash(), headers[2].hash()]
        );
    }

    #[test]
    fn stale_body_write_ack_cannot_start_a_retrys_deadline() {
        let headers = chain(3);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |hash| *hash == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let request = sync.next_requests_for(1)[0];
        let old_id = sync.body_request_id(&request).unwrap();
        assert!(sync.retry(&request));
        let new_id = sync.body_request_id(&request).unwrap();
        assert_ne!(old_id, new_id);
        sync.requests_sent_for_requests(1, &[(request, old_id)], 0);
        assert_eq!(sync.timeouts(u64::MAX), [] as [(BlockHash, u64); 0]);
        sync.requests_sent_for_requests(1, &[(request, new_id)], 100);
        assert_eq!(
            sync.timeouts(100 + REQUEST_TIMEOUT - 1),
            [] as [(BlockHash, u64); 0]
        );
        assert_eq!(sync.timeouts(100 + REQUEST_TIMEOUT), vec![(request, 1)]);
    }

    #[test]
    fn received_child_waiting_for_its_parent_does_not_blame_its_responsive_peer() {
        let headers = chain(3);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |hash| *hash == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let requested = sync.next_requests_for(1);
        let parent = requested[0];
        let child = requested[1];
        // Assign the dependency and its child to different onion streams.
        assert!(sync.request_failed(1, &child));
        assert_eq!(sync.next_requests_for(2), vec![child]);
        sync.requests_sent(1, &[parent], 0);
        let child_ticket = sync.body_request_id(&child).unwrap();
        sync.requests_sent_for_requests(2, &[(child, child_ticket)], 0);

        // The child arrived, but its body was discarded while the dependency
        // is unresolved. Only the peer withholding the parent should expire.
        assert!(sync.retry(&child));
        sync.requests_sent_for_requests(2, &[(child, child_ticket)], 1);
        assert_eq!(sync.timeouts(REQUEST_TIMEOUT), vec![(parent, 1)]);
        assert_eq!(sync.owner(&child), Some(2));
        assert_eq!(sync.timeouts(u64::MAX), [] as [(BlockHash, u64); 0]);

        assert_eq!(sync.next_requests_for(3), vec![parent]);
        assert!(sync.on_block(&parent));
        assert!(sync.retry(&child));
        let retry_ticket = sync.body_request_id(&child).unwrap();
        sync.requests_sent_for_requests(2, &[(child, retry_ticket)], 1_000);
        assert_eq!(
            sync.timeouts(1_000 + REQUEST_TIMEOUT - 1),
            [] as [(BlockHash, u64); 0]
        );
        assert_eq!(sync.timeouts(1_000 + REQUEST_TIMEOUT), vec![(child, 2)]);
    }

    #[test]
    fn missing_body_is_reassigned_only_by_its_owner() {
        let headers = chain(4);
        let mut sync = BlockSync::new();
        sync.on_headers(
            &headers[1..],
            |hash| *hash == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let requested = sync.next_requests_for(1);
        assert!(!sync.request_failed(9, &requested[0]));
        assert!(sync.request_failed(1, &requested[0]));
        assert!(!sync.request_failed(1, &requested[0]));
        let reassigned = sync.next_requests_for(2);
        assert_eq!(reassigned[0], requested[0]);
        assert_eq!(sync.owner(&requested[1]), Some(1));
    }

    #[test]
    fn refreshed_local_tip_work_blocks_further_body_requests() {
        use chain::target::U256;
        let headers = chain(5);
        let mut sync = BlockSync::new();
        let work = ChainWork::from_u256(U256::from(10));
        sync.on_headers(&headers[1..], |hash| *hash == headers[0].hash(), work, work)
            .unwrap();
        assert_eq!(sync.next_requests_for(1).len(), 2);
        sync.set_required_work(ChainWork::from_u256(U256::from(11)));
        assert_eq!(sync.next_requests_for(2), [] as [BlockHash; 0]);
    }

    #[test]
    fn configured_response_timeout_applies_to_written_headers_and_bodies() {
        let headers = chain(3);
        let mut sync = BlockSync::with_timeout(15);
        let ticket = sync.header_request_id().unwrap();
        sync.headers_sent_for_request(ticket, 100);
        assert!(!sync.headers_timed_out(114));
        assert!(sync.headers_timed_out(115));
        sync.on_headers(
            &headers[1..],
            |hash| *hash == headers[0].hash(),
            ChainWork::ZERO,
            MIN_CHAIN_WORK,
        )
        .unwrap();
        let hashes = sync.next_requests_for(1);
        sync.requests_sent(1, &hashes, 200);
        assert_eq!(sync.timeouts(214), [] as [(BlockHash, u64); 0]);
        assert_eq!(sync.timeouts(215).len(), hashes.len());
    }

    #[test]
    fn new_headers_leave_reassigned_older_bodies_ahead_of_the_spool() {
        let headers = chain(u32::try_from(MAX_HEADERS + 3).unwrap());
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(
                &headers[1..=MAX_HEADERS],
                |hash| *hash == headers[0].hash(),
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        let spooled = sync.take_received_headers(progress.queued);
        sync.queue_headers(&spooled[..2]).unwrap();
        let assigned = sync.next_requests_for(1);
        assert!(sync.next_headers_request().is_some());
        // The peer disappears while a continuation is already on the wire.
        sync.peer_disconnected(1);
        let progress = sync
            .on_headers(
                &headers[MAX_HEADERS + 1..],
                |_| false,
                ChainWork::ZERO,
                MIN_CHAIN_WORK,
            )
            .unwrap();
        let newly_spooled = sync.take_received_headers(progress.queued);
        assert_eq!(newly_spooled, headers[MAX_HEADERS + 1..]);
        // Only the new suffix was appended behind the unread spool. Bodies
        // from the disconnected stream still lead the in-memory queue.
        assert_eq!(sync.next_requests_for(2), assigned);
    }
}
