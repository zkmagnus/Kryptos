//! Headers-first synchronization: build a locator, accept a chained run
//! of headers, then download the bodies in order with bounded in-flight
//! requests and timeouts.
//!
//! Headers are requested one message at a time and only while the queue
//! of headers awaiting download is below a low-water mark, so the queue
//! never exceeds [`MAX_QUEUED_HEADERS`] however long the peer's chain is.

use std::collections::{HashMap, VecDeque};

use protocol::block::{BlockHash, BlockHeader};

use crate::message::{MAX_HEADERS, MAX_LOCATOR};
use crate::{Error, Result};

/// Block requests kept in flight at once.
pub const MAX_IN_FLIGHT: usize = 16;
/// Seconds before an unanswered block request is retried.
pub const REQUEST_TIMEOUT: u64 = 300;
/// More headers are requested only while fewer than this are queued.
pub const HEADERS_LOW_WATER: usize = 2 * MAX_HEADERS;
/// Most headers queued for download at once: the low-water mark plus one
/// full message. A peer that sends more misbehaves.
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

/// Download state.
#[derive(Debug)]
pub struct BlockSync {
    queue: VecDeque<BlockHeader>,
    in_flight: HashMap<BlockHash, u64>,
    last_header: Option<BlockHeader>,
    /// A headers request has been sent and not yet answered.
    headers_outstanding: bool,
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
    /// caller, has just been sent.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            in_flight: HashMap::new(),
            last_header: None,
            headers_outstanding: true,
            exhausted: false,
        }
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

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The last header accepted, the point to build the next locator from.
    pub fn last_header(&self) -> Option<&BlockHeader> {
        self.last_header.as_ref()
    }

    /// Accepts a requested headers message. `known` says whether we already
    /// have a block, so its body can be skipped. The first response starts
    /// at a known parent; every subsequent header must directly extend the
    /// last accepted header, even when both blocks are already known.
    ///
    /// # Errors
    /// Returns [`Error::BadHeaders`] on an unsolicited response, a gap,
    /// an out-of-order header, or more headers than the queue may hold.
    /// A rejected response leaves the download state unchanged.
    pub fn on_headers(
        &mut self,
        headers: &[BlockHeader],
        known: impl Fn(&BlockHash) -> bool,
    ) -> Result<Progress> {
        if !self.headers_outstanding {
            return Err(Error::BadHeaders("unsolicited headers"));
        }
        if headers.len() > MAX_HEADERS {
            return Err(Error::BadHeaders("too many headers"));
        }
        if self.queue.len().saturating_add(headers.len()) > MAX_QUEUED_HEADERS {
            return Err(Error::BadHeaders("queue full"));
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
        self.headers_outstanding = false;
        self.exhausted = headers.len() < MAX_HEADERS;
        Ok(Progress {
            queued,
            exhausted: self.exhausted,
        })
    }

    /// The header to continue from if more headers should be requested
    /// now: the peer has more, no request is outstanding, and the queue
    /// is below the low-water mark. Marks the request as sent.
    pub fn next_headers_request(&mut self) -> Option<BlockHash> {
        if self.exhausted || self.headers_outstanding || self.queue.len() >= HEADERS_LOW_WATER {
            return None;
        }
        let from = self.last_header.as_ref()?.hash();
        self.headers_outstanding = true;
        Some(from)
    }

    /// Block hashes to request now, filling the in-flight window.
    pub fn next_requests(&mut self, now: u64) -> Vec<BlockHash> {
        let mut requests = Vec::new();
        while self.in_flight.len() < MAX_IN_FLIGHT {
            let Some(header) = self.queue.pop_front() else {
                break;
            };
            let hash = header.hash();
            self.in_flight.insert(hash, now);
            requests.push(hash);
        }
        requests
    }

    /// Whether this block is still awaiting successful import.
    pub fn expects(&self, hash: &BlockHash) -> bool {
        self.in_flight.contains_key(hash)
    }

    /// Restarts the deadline for an unresolved block requested again after
    /// its missing parent becomes available. Returns whether it was expected.
    pub fn retry(&mut self, hash: &BlockHash, now: u64) -> bool {
        let Some(sent) = self.in_flight.get_mut(hash) else {
            return false;
        };
        *sent = now;
        true
    }

    /// Acknowledges a successfully imported block; returns whether it was
    /// expected. Receipt alone must not remove an unresolved dependency.
    pub fn on_block(&mut self, hash: &BlockHash) -> bool {
        self.in_flight.remove(hash).is_some()
    }

    /// Requests that have timed out, re-queued for another peer.
    pub fn timeouts(&mut self, now: u64) -> Vec<BlockHash> {
        let expired: Vec<BlockHash> = self
            .in_flight
            .iter()
            .filter(|(_, sent)| now.saturating_sub(**sent) >= REQUEST_TIMEOUT)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.in_flight.remove(hash);
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
        let progress = sync.on_headers(&headers[1..], |h| *h == genesis).unwrap();
        assert_eq!(
            progress,
            Progress {
                queued: 4,
                exhausted: true
            }
        );
        assert_eq!(sync.last_header().unwrap().height, 4);
        let requests = sync.next_requests(0);
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
            .on_headers(&headers[1..], |h| known.contains(h))
            .unwrap();
        assert_eq!(progress.queued, 3);
        let mut bad = BlockSync::new();
        assert!(matches!(
            bad.on_headers(&headers[2..], |h| *h == headers[0].hash()),
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
        sync.on_headers(&headers[1..=MAX_HEADERS], |h| *h == headers[0].hash())
            .unwrap();
        assert!(!sync.exhausted());
        let from = sync.next_headers_request().unwrap();
        assert_eq!(from, headers[MAX_HEADERS].hash());
        assert_eq!(sync.next_headers_request(), None, "one at a time");

        sync.on_headers(&headers[MAX_HEADERS + 1..], |_| false)
            .unwrap();
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);
        assert_eq!(sync.next_headers_request(), None, "queue at the mark");

        let requested = sync.next_requests(0);
        for hash in &requested {
            sync.on_block(hash);
        }
        assert!(sync.next_headers_request().is_some(), "queue drained");
    }

    #[test]
    fn unsolicited_headers_cannot_overfill_queue_and_exhaustion_stops_requests() {
        let headers = chain(u32::try_from(MAX_QUEUED_HEADERS + 2).unwrap());
        let mut sync = BlockSync::new();
        sync.on_headers(&headers[1..=MAX_HEADERS], |h| *h == headers[0].hash())
            .unwrap();
        assert!(sync.next_headers_request().is_some());
        sync.on_headers(&headers[MAX_HEADERS + 1..=HEADERS_LOW_WATER], |_| false)
            .unwrap();
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);
        assert_eq!(sync.next_headers_request(), None);
        assert!(matches!(
            sync.on_headers(&headers[HEADERS_LOW_WATER + 1..=MAX_QUEUED_HEADERS], |_| {
                false
            }),
            Err(Error::BadHeaders("unsolicited headers"))
        ));
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);

        let mut short = BlockSync::new();
        short
            .on_headers(&headers[1..3], |h| *h == headers[0].hash())
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
            sync.on_headers(&repeated, |_| true),
            Err(Error::BadHeaders("gap"))
        ));
        assert!(sync.is_idle());
        assert!(!sync.exhausted());
        assert!(sync.last_header().is_none());
        // Rejection preserves the outstanding request, so an honest response
        // can still fulfill it instead of being treated as unsolicited.
        let progress = sync
            .on_headers(&headers[1..], |hash| *hash == headers[0].hash())
            .unwrap();
        assert_eq!(progress.queued, 2);
    }

    #[test]
    fn known_parents_do_not_allow_gaps_or_partial_queue_updates() {
        let headers = chain(5);
        let mut sync = BlockSync::new();
        let disordered = [headers[1].clone(), headers[3].clone()];
        assert!(matches!(
            sync.on_headers(&disordered, |hash| {
                *hash == headers[0].hash() || *hash == headers[2].hash()
            }),
            Err(Error::BadHeaders("gap"))
        ));
        // The first unknown header must not have leaked into the queue.
        assert!(sync.is_idle());
        assert!(sync.last_header().is_none());
        assert!(!sync.exhausted());
        let progress = sync
            .on_headers(&headers[1..], |hash| *hash == headers[0].hash())
            .unwrap();
        assert_eq!(progress.queued, 4);
    }

    #[test]
    fn continuation_must_extend_requested_hash_even_when_replayed_blocks_are_known() {
        let headers = chain(u32::try_from(MAX_HEADERS + 3).unwrap());
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(&headers[1..=MAX_HEADERS], |_| true)
            .unwrap();
        assert_eq!(progress.queued, 0);
        assert!(!progress.exhausted);
        assert_eq!(
            sync.next_headers_request(),
            Some(headers[MAX_HEADERS].hash())
        );
        assert!(matches!(
            sync.on_headers(&headers[1..=MAX_HEADERS], |_| true),
            Err(Error::BadHeaders("gap"))
        ));
        assert_eq!(
            sync.last_header().unwrap().hash(),
            headers[MAX_HEADERS].hash()
        );
        assert!(!sync.exhausted());
        assert!(sync.is_idle());

        let progress = sync
            .on_headers(&headers[MAX_HEADERS + 1..], |_| false)
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
            sync.on_headers(&headers[1..], |_| true),
            Err(Error::BadHeaders("too many headers"))
        ));
        assert!(sync.last_header().is_none());
        assert!(sync.is_idle());
        assert!(!sync.exhausted());
        sync.on_headers(&headers[1..=MAX_HEADERS], |_| true)
            .unwrap();
        assert!(matches!(
            sync.on_headers(&[], |_| true),
            Err(Error::BadHeaders("unsolicited headers"))
        ));
        assert!(!sync.exhausted());
        assert!(sync.next_headers_request().is_some());
        let done = sync.on_headers(&[], |_| true).unwrap();
        assert_eq!(done.queued, 0);
        assert!(done.exhausted);
        assert!(sync.is_idle());
        assert_eq!(
            sync.last_header().unwrap().height,
            u32::try_from(MAX_HEADERS).unwrap()
        );
    }

    #[test]
    fn in_flight_is_bounded_and_timeouts_requeue() {
        let headers = chain(40);
        let mut sync = BlockSync::new();
        sync.on_headers(&headers[1..], |h| *h == headers[0].hash())
            .unwrap();
        let first = sync.next_requests(0);
        assert_eq!(first.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.queued(), 39 - MAX_IN_FLIGHT);
        assert_eq!(sync.next_requests(1).len(), 0);
        assert_eq!(sync.timeouts(REQUEST_TIMEOUT - 1).len(), 0);
        let expired = sync.timeouts(REQUEST_TIMEOUT);
        assert_eq!(expired.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.in_flight(), 0);
    }

    #[test]
    fn unresolved_bodies_remain_expected_and_retry_extends_the_deadline() {
        let headers = chain(3);
        let mut sync = BlockSync::new();
        sync.on_headers(&headers[1..], |hash| *hash == headers[0].hash())
            .unwrap();
        sync.next_requests(0);
        let parent = headers[1].hash();
        let child = headers[2].hash();
        assert!(sync.expects(&child));
        // An out-of-order child has not been successfully imported, so it
        // remains tracked while its parent is acknowledged.
        assert!(sync.on_block(&parent));
        assert!(!sync.expects(&parent));
        assert!(sync.expects(&child));
        assert!(!sync.is_idle());
        assert!(sync.retry(&child, REQUEST_TIMEOUT - 1));
        assert!(!sync.retry(&parent, REQUEST_TIMEOUT - 1));
        assert_eq!(sync.timeouts(REQUEST_TIMEOUT), [] as [BlockHash; 0]);
        assert_eq!(sync.timeouts(2 * REQUEST_TIMEOUT - 1), vec![child]);
        assert!(!sync.expects(&child));
        assert!(sync.is_idle());
    }
}
