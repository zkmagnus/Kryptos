//! Known peer addresses, bans, and candidates for outbound connections.

use std::collections::HashMap;

use protocol::bytes::{Reader, Writer};
use rand_core::RngCore;

use crate::address::{NetAddr, PeerKey};
use crate::message::{put_count, take_count, PeerAddr, MAX_ADDRESSES};
use crate::{Error, Result};

/// Addresses the book keeps at most.
pub const MAX_KNOWN: usize = 10_000;
/// Seconds an address timestamp may be in the future before it is ignored.
pub const MAX_FUTURE: u64 = 10 * 60;
/// Seconds after which an unseen address is forgotten.
pub const MAX_AGE: u64 = 30 * 24 * 60 * 60;
/// Default ban length in seconds.
pub const BAN_SECONDS: u64 = 24 * 60 * 60;
/// Service identities with remembered penalties at most.
pub const MAX_BANS: usize = 10_000;
/// Seconds a successful outbound handshake vouches for an address.
pub const VERIFIED_SECONDS: u64 = 24 * 60 * 60;
/// Minimum time between attempts, doubling after each failure up to
/// [`MAX_RETRY_SECONDS`].
pub const RETRY_SECONDS: u64 = 60;
/// Longest delay between attempts at an address that keeps failing.
pub const MAX_RETRY_SECONDS: u64 = 60 * 60;
/// Failures after which the retry delay stops doubling; bounds the shift.
const MAX_BACKOFF_DOUBLINGS: u32 = 6;
/// Granularity of the timestamp on shared addresses. Every address in a
/// sample carries the same rounded time, so a peer cannot tell from it
/// when, or in which order, this node connected to each one.
pub const SHARED_TIME_GRANULARITY: u64 = 60 * 60;

// Older development snapshots began directly with a version byte.
const SNAPSHOT_MAGIC: &[u8; 4] = b"RHPA";
/// Version byte of the [`Snapshot`] layout.
pub const SNAPSHOT_VERSION: u8 = 1;
/// Largest peer snapshot this node can encode, in bytes.
pub const MAX_SNAPSHOT_BYTES: usize = SNAPSHOT_MAGIC.len() + 9 + MAX_KNOWN * 65 + MAX_BANS * 44;

#[derive(Clone, Copy, Debug)]
struct Entry {
    addr: PeerAddr,
    failures: u32,
    verified_at: Option<u64>,
    retry_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Penalty {
    score: u32,
    until: u64,
}

impl Entry {
    /// Whether a recent outbound handshake verified this address.
    fn is_verified(&self, now: u64) -> bool {
        self.verified_at
            .is_some_and(|at| now.saturating_sub(at) < VERIFIED_SECONDS)
    }
}

/// The address book.
#[derive(Debug, Default)]
pub struct AddressBook {
    entries: HashMap<PeerKey, Entry>,
    /// Penalties apply to the service identity, across all virtual ports.
    bans: HashMap<NetAddr, Penalty>,
    own: Option<NetAddr>,
}

impl AddressBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known addresses.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the book is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records a new address. Addresses from the future or too old are
    /// ignored, and the book stays bounded. Gossip never refreshes a known
    /// entry, only [`AddressBook::connected`] does, so a peer re-sending an
    /// address cannot keep it alive past [`MAX_AGE`]. A slightly future
    /// timestamp is stored as `now` for the same reason.
    pub fn add(&mut self, addr: PeerAddr, now: u64) -> bool {
        if self.own == Some(addr.addr)
            || addr.port == 0
            || addr.last_seen > now.saturating_add(MAX_FUTURE)
            || now.saturating_sub(addr.last_seen) > MAX_AGE
            || self.entries.contains_key(&addr.key())
            || self.entries.len() >= MAX_KNOWN
        {
            return false;
        }
        self.entries.insert(
            addr.key(),
            Entry {
                addr: PeerAddr {
                    last_seen: addr.last_seen.min(now),
                    ..addr
                },
                failures: 0,
                verified_at: None,
                retry_at: 0,
            },
        );
        true
    }

    /// Records addresses received in an `Addr` message, at most the
    /// protocol limit, and returns how many were new.
    pub fn add_many(&mut self, addrs: impl IntoIterator<Item = PeerAddr>, now: u64) -> usize {
        addrs
            .into_iter()
            .take(MAX_ADDRESSES)
            .filter(|a| self.add(*a, now))
            .count()
    }

    /// Sets our own service identity and removes it from the peer table.
    pub fn set_own(&mut self, own: Option<NetAddr>) {
        self.own = own;
        self.entries.retain(|(address, _), _| Some(*address) != own);
        self.bans.retain(|address, _| Some(*address) != own);
    }

    fn penalty(&mut self, address: NetAddr) -> &mut Penalty {
        if !self.bans.contains_key(&address) && self.bans.len() >= MAX_BANS {
            let soonest = self
                .bans
                .iter()
                .min_by_key(|(address, penalty)| (penalty.until, **address))
                .map(|(address, _)| *address);
            if let Some(soonest) = soonest {
                self.bans.remove(&soonest);
            }
        }
        self.bans
            .entry(address)
            .or_insert(Penalty { score: 0, until: 0 })
    }

    /// Bans a service identity, including its other ports.
    pub fn ban(&mut self, address: NetAddr, now: u64) {
        let penalty = self.penalty(address);
        penalty.score = penalty.score.max(crate::peer::BAN_THRESHOLD);
        penalty.until = now.saturating_add(BAN_SECONDS);
    }

    /// Accumulates behavior penalties across connections and restarts.
    /// Reaching the standard peer threshold bans the service identity.
    pub fn penalize(&mut self, address: NetAddr, points: u32, now: u64) {
        let penalty = self.penalty(address);
        penalty.score = penalty.score.saturating_add(points);
        if penalty.score >= crate::peer::BAN_THRESHOLD {
            penalty.until = now.saturating_add(BAN_SECONDS);
        }
    }

    /// Remembered behavior score for a service identity.
    pub fn score(&self, address: &NetAddr) -> u32 {
        self.bans.get(address).map_or(0, |penalty| penalty.score)
    }

    /// Whether the service identity is banned at `now`.
    pub fn is_banned(&self, address: &NetAddr, now: u64) -> bool {
        self.bans
            .get(address)
            .is_some_and(|penalty| penalty.until > now)
    }

    /// Whether policy and retry backoff permit dialing this endpoint now.
    /// An unknown endpoint may be admitted by explicit configuration.
    pub fn dialable(&self, key: PeerKey, now: u64) -> bool {
        self.own != Some(key.0)
            && !self.is_banned(&key.0, now)
            && self
                .entries
                .get(&key)
                .is_none_or(|entry| entry.retry_at <= now)
    }

    /// Records a failed connection attempt.
    pub fn failed(&mut self, key: PeerKey) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.failures = e.failures.saturating_add(1);
            e.verified_at = None;
        }
    }

    /// Reserves an address while dialing and applies a bounded retry delay.
    pub fn attempted(&mut self, key: PeerKey, now: u64) {
        if let Some(e) = self.entries.get_mut(&key) {
            let delay = RETRY_SECONDS
                .saturating_mul(1u64 << e.failures.min(MAX_BACKOFF_DOUBLINGS))
                .min(MAX_RETRY_SECONDS);
            e.retry_at = now.saturating_add(delay);
        }
    }

    /// Consecutive failed attempts at an endpoint.
    pub fn failures(&self, key: PeerKey) -> u32 {
        self.entries.get(&key).map_or(0, |entry| entry.failures)
    }

    /// Applies the node's configured backoff, measured from failure/disconnection.
    pub fn defer_retry(&mut self, key: PeerKey, now: u64, seconds: u64) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.retry_at = now.saturating_add(seconds);
        }
    }

    /// Records a successful connection at `now`.
    pub fn connected(&mut self, key: PeerKey, now: u64) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.failures = 0;
            e.retry_at = 0;
            e.addr.last_seen = now;
            e.verified_at = Some(now);
        }
    }

    /// A random unbanned address not in `exclude`, preferring those that
    /// have failed less.
    pub fn candidate(
        &self,
        exclude: &[PeerKey],
        now: u64,
        rng: &mut impl RngCore,
    ) -> Option<PeerAddr> {
        self.select_candidate(exclude, now, rng, false)
    }

    /// An unverified candidate for a bounded reachability probe.
    pub fn unverified_candidate(
        &self,
        exclude: &[PeerKey],
        now: u64,
        rng: &mut impl RngCore,
    ) -> Option<PeerAddr> {
        self.select_candidate(exclude, now, rng, true)
    }

    fn select_candidate(
        &self,
        exclude: &[PeerKey],
        now: u64,
        rng: &mut impl RngCore,
        unverified_only: bool,
    ) -> Option<PeerAddr> {
        let mut pool: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| {
                e.retry_at <= now
                    && (!unverified_only || !e.is_verified(now))
                    && now.saturating_sub(e.addr.last_seen) <= MAX_AGE
                    && !self.is_banned(&e.addr.addr, now)
                    && !exclude.iter().any(|(addr, _)| *addr == e.addr.addr)
            })
            .collect();
        if pool.is_empty() {
            return None;
        }
        pool.sort_by_key(|e| (self.score(&e.addr.addr), e.failures, e.addr.key()));
        let best = pool
            .first()
            .map_or((0, 0), |e| (self.score(&e.addr.addr), e.failures));
        let good: Vec<&Entry> = pool
            .iter()
            .copied()
            .filter(|e| (self.score(&e.addr.addr), e.failures) == best)
            .collect();
        crate::random::index(rng, good.len())
            .and_then(|i| good.get(i))
            .map(|e| e.addr)
    }

    /// Whether a recent outbound handshake verified this address.
    pub fn verified(&self, key: PeerKey, now: u64) -> bool {
        self.entries.get(&key).is_some_and(|e| e.is_verified(now))
    }

    /// A random sample of recently verified, unbanned addresses to share.
    /// Gossip cannot extend the lifetime of our own reachability checks.
    /// Every address carries `now` rounded down to
    /// [`SHARED_TIME_GRANULARITY`] rather than its verification time, which
    /// would single out the peers this node is connected to right now.
    pub fn sample(&self, count: usize, now: u64, rng: &mut impl RngCore) -> Vec<PeerAddr> {
        let shared_time = now.saturating_sub(now % SHARED_TIME_GRANULARITY);
        let mut pool: Vec<PeerAddr> = self
            .entries
            .values()
            .filter(|e| e.is_verified(now) && !self.is_banned(&e.addr.addr, now))
            .map(|e| PeerAddr {
                last_seen: shared_time,
                ..e.addr
            })
            .collect();
        for i in (1..pool.len()).rev() {
            let j = crate::random::index(rng, i.saturating_add(1)).unwrap_or(0);
            pool.swap(i, j);
        }
        pool.truncate(count.min(MAX_ADDRESSES));
        pool
    }

    /// Forgets addresses unseen for longer than [`MAX_AGE`] and expired bans.
    pub fn prune(&mut self, now: u64) {
        self.entries
            .retain(|_, e| now.saturating_sub(e.addr.last_seen) <= MAX_AGE);
        self.bans
            .retain(|_, penalty| penalty.until > now || penalty.score != 0);
    }

    /// Recently verified, unbanned peers to retain as restart anchors.
    /// Preference is by behavior, connection failures, and verification recency.
    pub fn anchors(&self, count: usize, now: u64) -> Vec<PeerAddr> {
        let mut entries: Vec<_> = self
            .entries
            .values()
            .filter(|entry| entry.is_verified(now) && !self.is_banned(&entry.addr.addr, now))
            .collect();
        entries.sort_by_key(|entry| {
            (
                self.score(&entry.addr.addr),
                entry.failures,
                core::cmp::Reverse(entry.verified_at),
                entry.addr.key(),
            )
        });
        entries
            .into_iter()
            .take(count)
            .map(|entry| entry.addr)
            .collect()
    }

    /// Addresses, connection history, and behavior penalties in canonical order.
    pub fn snapshot(&self) -> Snapshot {
        let mut entries: Vec<SavedAddr> = self
            .entries
            .values()
            .map(|entry| SavedAddr {
                addr: entry.addr,
                verified_at: entry.verified_at,
                failures: entry.failures,
                retry_at: entry.retry_at,
            })
            .collect();
        entries.sort_by_key(|entry| entry.addr.key());
        let mut penalties: Vec<_> = self
            .bans
            .iter()
            .map(|(address, penalty)| SavedPenalty {
                addr: *address,
                score: penalty.score,
                until: penalty.until,
            })
            .collect();
        penalties.sort_by_key(|penalty| penalty.addr);
        Snapshot { entries, penalties }
    }

    /// Restores saved peer state under the normal timestamp and size limits.
    /// Untrusted future verification, retry, and ban times are bounded.
    pub fn restore(
        &mut self,
        snapshot: Snapshot,
        now: u64,
        keep: impl Fn(&PeerAddr) -> bool,
    ) -> usize {
        let own = self.own;
        for saved in snapshot
            .penalties
            .into_iter()
            .filter(|saved| Some(saved.addr) != own)
        {
            let penalty = self.penalty(saved.addr);
            penalty.score = penalty.score.max(saved.score);
            penalty.until = penalty
                .until
                .max(saved.until.min(now.saturating_add(BAN_SECONDS)));
        }
        let mut added: usize = 0;
        for saved in snapshot
            .entries
            .into_iter()
            .filter(|saved| keep(&saved.addr))
        {
            if !self.add(saved.addr, now) {
                continue;
            }
            if let Some(entry) = self.entries.get_mut(&saved.addr.key()) {
                entry.verified_at = saved.verified_at.filter(|at| *at <= now);
                entry.failures = saved.failures;
                entry.retry_at = saved.retry_at.min(now.saturating_add(MAX_RETRY_SECONDS));
            }
            added = added.saturating_add(1);
        }
        added
    }
}

/// One saved peer endpoint and its connection history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedAddr {
    /// The address and when it was last seen alive.
    pub addr: PeerAddr,
    /// Last verified outbound handshake, if any.
    pub verified_at: Option<u64>,
    /// Consecutive failed attempts.
    pub failures: u32,
    /// Earliest permitted retry time.
    pub retry_at: u64,
}

/// Persistent behavior associated with a Tor service identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedPenalty {
    /// The service identity, applying across ports.
    pub addr: NetAddr,
    /// Accumulated misbehavior score.
    pub score: u32,
    /// Ban expiry, or zero when there is no active ban.
    pub until: u64,
}

/// Restart state, versioned separately from chain storage.
/// Entries and penalties are each stored in strictly ascending identity order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    entries: Vec<SavedAddr>,
    penalties: Vec<SavedPenalty>,
}

impl Snapshot {
    /// Saved endpoints, in ascending identity/port order.
    pub fn entries(&self) -> &[SavedAddr] {
        &self.entries
    }

    /// Saved behavior scores and ban expirations.
    pub fn penalties(&self) -> &[SavedPenalty] {
        &self.penalties
    }

    /// The canonical peer-state encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.put(SNAPSHOT_MAGIC).put_u8(SNAPSHOT_VERSION);
        put_count(&mut writer, self.entries.len());
        for saved in &self.entries {
            saved.addr.write(&mut writer);
            match saved.verified_at {
                Some(at) => writer.put_u8(1).put_u64_le(at),
                None => writer.put_u8(0),
            };
            writer
                .put(&saved.failures.to_le_bytes())
                .put_u64_le(saved.retry_at);
        }
        put_count(&mut writer, self.penalties.len());
        for saved in &self.penalties {
            let NetAddr::TorV3(key) = saved.addr;
            writer
                .put(&key)
                .put(&saved.score.to_le_bytes())
                .put_u64_le(saved.until);
        }
        writer.into_bytes()
    }

    /// Decodes peer state, rejecting snapshots from earlier development builds.
    ///
    /// # Errors
    /// Fails on a wrong magic prefix, unknown versions, unbounded counts,
    /// duplicates, out-of-order identities, bad flags, truncation, or trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.take(SNAPSHOT_MAGIC.len())? != SNAPSHOT_MAGIC {
            return Err(Error::BadSnapshot("unknown format"));
        }
        if reader.take_u8()? != SNAPSHOT_VERSION {
            return Err(Error::BadSnapshot("unknown version"));
        }
        let count = take_count(&mut reader, MAX_KNOWN, "saved addresses")?;
        let mut entries: Vec<SavedAddr> = Vec::with_capacity(count);
        for _ in 0..count {
            let saved = read_saved(&mut reader)?;
            if entries
                .last()
                .is_some_and(|previous| previous.addr.key() >= saved.addr.key())
            {
                return Err(Error::BadSnapshot("addresses not strictly ascending"));
            }
            entries.push(saved);
        }
        let count = take_count(&mut reader, MAX_BANS, "saved penalties")?;
        let mut penalties: Vec<SavedPenalty> = Vec::with_capacity(count);
        for _ in 0..count {
            let saved = SavedPenalty {
                addr: NetAddr::TorV3(reader.take_array()?),
                score: u32::from_le_bytes(reader.take_array()?),
                until: reader.take_u64_le()?,
            };
            if penalties
                .last()
                .is_some_and(|previous| previous.addr >= saved.addr)
            {
                return Err(Error::BadSnapshot("penalties not strictly ascending"));
            }
            penalties.push(saved);
        }
        reader.finish()?;
        Ok(Self { entries, penalties })
    }
}

fn read_saved(reader: &mut Reader<'_>) -> Result<SavedAddr> {
    let addr = PeerAddr::read(reader)?;
    let verified_at = match reader.take_u8()? {
        0 => None,
        1 => Some(reader.take_u64_le()?),
        _ => return Err(Error::BadSnapshot("verified flag is not 0 or 1")),
    };
    let failures = u32::from_le_bytes(reader.take_array()?);
    let retry_at = reader.take_u64_le()?;
    Ok(SavedAddr {
        addr,
        verified_at,
        failures,
        retry_at,
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn addr(last: u8, seen: u64) -> PeerAddr {
        PeerAddr::new(NetAddr::TorV3([last; 32]), 1234, seen)
    }

    #[test]
    fn adds_deduplicates_and_gossip_does_not_refresh_known_entries() {
        let mut book = AddressBook::new();
        assert!(book.add(addr(1, 100), 100));
        assert!(!book.add(addr(1, 150), 200));
        assert_eq!(book.len(), 1);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(book.candidate(&[], 200, &mut rng).unwrap().last_seen, 100);
    }

    #[test]
    fn re_gossiped_addresses_still_expire_but_handshakes_keep_them() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        let later = 100 + MAX_AGE;
        book.add(addr(1, later), later);
        book.connected(addr(2, 0).key(), later);
        book.prune(later + 1);
        assert_eq!(book.len(), 1);
        assert!(book.verified(addr(2, 0).key(), later + 1));
    }

    #[test]
    fn future_timestamps_are_stored_as_now() {
        let mut book = AddressBook::new();
        assert!(book.add(addr(1, 100 + MAX_FUTURE), 100));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert_eq!(book.candidate(&[], 100, &mut rng).unwrap().last_seen, 100);
    }

    #[test]
    fn future_and_ancient_addresses_are_ignored() {
        let mut book = AddressBook::new();
        assert!(!book.add(addr(1, 10_000), 100));
        assert!(!book.add(addr(2, 0), MAX_AGE + 100));
        assert!(book.is_empty());
    }

    #[test]
    fn bans_exclude_candidates_and_samples_until_they_expire() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.ban(addr(1, 0).addr, 100);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert!(book.is_banned(&addr(1, 0).addr, 100));
        assert!(book.candidate(&[], 100, &mut rng).is_none());
        assert_eq!(book.sample(5, 100, &mut rng).len(), 0);
        assert!(book.candidate(&[], 100 + BAN_SECONDS, &mut rng).is_some());
        book.prune(100 + BAN_SECONDS);
        assert!(!book.is_banned(&addr(1, 0).addr, 100 + BAN_SECONDS));
    }

    #[test]
    fn a_ban_covers_every_port_of_the_identity_and_adds_no_address() {
        let mut book = AddressBook::new();
        let inbound = PeerAddr::new(NetAddr::TorV3([9; 32]), 51_234, 100);
        book.ban(inbound.addr, 100);
        let reconnect = PeerAddr::new(NetAddr::TorV3([9; 32]), 51_999, 100);
        assert!(
            book.is_banned(&reconnect.addr, 100),
            "a different virtual port"
        );
        assert!(
            !book.is_banned(&addr(1, 0).addr, 100),
            "other service identities are fine"
        );
        assert!(
            book.is_empty(),
            "a banned inbound port is not a dial candidate"
        );
    }

    #[test]
    fn the_ban_list_is_bounded_and_evicts_the_ban_ending_soonest() {
        let mut book = AddressBook::new();
        let ip = |i: usize| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_le_bytes());
            NetAddr::TorV3(key)
        };
        for i in 0..MAX_BANS {
            book.ban(ip(i), i as u64);
        }
        book.ban(ip(MAX_BANS), MAX_BANS as u64);
        assert_eq!(book.bans.len(), MAX_BANS);
        assert!(!book.is_banned(&ip(0), 0), "the earliest ban made room");
        assert!(book.is_banned(&ip(MAX_BANS), MAX_BANS as u64));
    }

    #[test]
    fn candidates_skip_excluded_and_prefer_fewer_failures() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        book.failed(addr(1, 0).key());
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        for _ in 0..10 {
            assert_eq!(
                book.candidate(&[], 100, &mut rng).unwrap().addr,
                addr(2, 0).addr
            );
        }
        assert_eq!(
            book.candidate(&[addr(2, 0).key()], 100, &mut rng)
                .unwrap()
                .addr,
            addr(1, 0).addr
        );
        book.connected(addr(1, 0).key(), 300);
        assert_eq!(book.add_many([addr(3, 300), addr(3, 300)], 300), 1);
    }

    #[test]
    fn sample_is_bounded_and_prune_forgets_old_entries() {
        let mut book = AddressBook::new();
        for i in 1..=20u8 {
            book.add(addr(i, 100), 100);
            book.connected(addr(i, 100).key(), 100);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        assert_eq!(book.sample(5, 100, &mut rng).len(), 5);
        book.prune(100 + MAX_AGE + 1);
        assert!(book.is_empty());
    }

    #[test]
    fn gossip_is_shared_only_after_verification_and_cannot_renew_it() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        book.add(addr(1, 100), 100);
        assert_eq!(book.sample(100, 100, &mut rng).len(), 0);
        book.connected(addr(1, 100).key(), 100);
        assert!(book.unverified_candidate(&[], 100, &mut rng).is_none());
        book.add(addr(1, 200), 200);
        assert_eq!(book.sample(100, 200, &mut rng), vec![addr(1, 0)]);
        assert_eq!(book.sample(100, 100 + VERIFIED_SECONDS, &mut rng).len(), 0);
        assert!(book
            .unverified_candidate(&[], 100 + VERIFIED_SECONDS, &mut rng)
            .is_some());
        book.connected(addr(1, 100).key(), 300);
        book.failed(addr(1, 100).key());
        assert_eq!(book.sample(100, 300, &mut rng).len(), 0);
    }

    #[test]
    fn shared_timestamps_are_rounded_and_identical() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let now = 5 * SHARED_TIME_GRANULARITY + 17;
        for (i, seen) in [(1, now - 1_000), (2, now - 1)] {
            book.add(addr(i, seen), seen);
            book.connected(addr(i, 0).key(), seen);
        }
        let sample = book.sample(100, now, &mut rng);
        assert_eq!(sample.len(), 2);
        assert!(sample
            .iter()
            .all(|a| a.last_seen == 5 * SHARED_TIME_GRANULARITY));
    }

    #[test]
    fn retry_delay_doubles_and_is_capped() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        book.add(addr(1, 100), 100);
        for _ in 0..=MAX_BACKOFF_DOUBLINGS {
            book.failed(addr(1, 0).key());
        }
        book.attempted(addr(1, 0).key(), 100);
        let retry = 100 + MAX_RETRY_SECONDS;
        assert!(book.candidate(&[], retry - 1, &mut rng).is_none());
        assert!(book.candidate(&[], retry, &mut rng).is_some());
    }

    #[test]
    fn failed_candidates_back_off_even_when_announced_again() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let a = addr(1, 100);
        book.add(a, 100);
        book.attempted(a.key(), 100);
        book.failed(a.key());
        book.add(addr(1, 110), 110);
        assert!(book.candidate(&[], 159, &mut rng).is_none());
        assert!(book.candidate(&[], 160, &mut rng).is_some());
        book.attempted(a.key(), 160);
        assert!(book.candidate(&[], 279, &mut rng).is_none());
        assert!(book.candidate(&[], 280, &mut rng).is_some());
    }

    fn saved_book() -> AddressBook {
        let mut book = AddressBook::new();
        book.add(addr(3, 100), 100);
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        book.connected(addr(2, 0).key(), 150);
        book
    }

    #[test]
    fn snapshots_roundtrip_in_canonical_order() {
        let snapshot = saved_book().snapshot();
        let keys: Vec<_> = snapshot.entries().iter().map(|s| s.addr.key()).collect();
        assert_eq!(
            keys,
            vec![addr(1, 0).key(), addr(2, 0).key(), addr(3, 0).key()]
        );
        assert_eq!(snapshot.entries()[1].verified_at, Some(150));
        let bytes = snapshot.to_bytes();
        assert_eq!(Snapshot::from_bytes(&bytes).unwrap(), snapshot);
        assert_eq!(bytes, saved_book().snapshot().to_bytes(), "deterministic");
        assert!(bytes.starts_with(b"RHPA\x01"));
        assert_eq!(
            bytes.len(),
            SNAPSHOT_MAGIC.len() + 1 + 4 + 3 * (36 + 8 + 1 + 4 + 8) + 8 + 4
        );
    }

    #[test]
    fn snapshots_reject_garbage() {
        let good = saved_book().snapshot().to_bytes();
        let version_at = SNAPSHOT_MAGIC.len();
        let count_at = version_at + 1;
        let flag_at = count_at + 4 + 36 + 8;
        let mut bad_version = good.clone();
        bad_version[version_at] = 2;
        let legacy_tor = bad_version[version_at..].to_vec();
        let mut bad_flag = good.clone();
        bad_flag[flag_at] = 2;
        let mut too_many = good.clone();
        too_many
            .get_mut(count_at..count_at + 4)
            .unwrap()
            .copy_from_slice(&u32::try_from(MAX_KNOWN + 1).unwrap().to_le_bytes());
        let saved = saved_book().snapshot();
        let duplicate = Snapshot {
            entries: vec![saved.entries[0], saved.entries[0]],
            penalties: Vec::new(),
        }
        .to_bytes();
        let mut reversed = saved.clone();
        reversed.entries.reverse();
        let trailing = [good.as_slice(), &[0]].concat();
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("legacy IP snapshot", vec![1, 0, 0, 0, 0]),
            ("legacy Tor snapshot", legacy_tor),
            ("version", bad_version),
            ("flag", bad_flag),
            ("count", too_many),
            ("duplicate", duplicate),
            ("order", reversed.to_bytes()),
            ("truncated", good[..good.len().saturating_sub(1)].to_vec()),
            ("trailing", trailing),
        ] {
            assert!(Snapshot::from_bytes(&bytes).is_err(), "{name} accepted");
        }
    }

    #[test]
    fn own_service_is_rejected_on_every_port_and_never_gossiped() {
        let mut book = saved_book();
        book.set_own(Some(addr(2, 0).addr));
        assert_eq!(book.len(), 2);
        assert!(!book.add(PeerAddr::new(addr(2, 0).addr, 5678, 200), 200));
        assert_eq!(book.restore(saved_book().snapshot(), 200, |_| true), 0);
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        assert!(book
            .sample(100, 200, &mut rng)
            .iter()
            .all(|peer| peer.addr != addr(2, 0).addr));
    }

    #[test]
    fn restart_retains_penalties_failures_and_retry_deadlines() {
        let mut original = saved_book();
        original.failed(addr(1, 0).key());
        original.attempted(addr(1, 0).key(), 200);
        original.penalize(addr(2, 0).addr, 40, 200);
        original.penalize(addr(3, 0).addr, 100, 200);
        let snapshot = Snapshot::from_bytes(&original.snapshot().to_bytes()).unwrap();
        let mut restored = AddressBook::new();
        assert_eq!(restored.restore(snapshot, 201, |_| true), 3);
        assert_eq!(restored.score(&addr(2, 0).addr), 40);
        assert!(restored.is_banned(&addr(3, 0).addr, 201));
        assert_eq!(restored.entries.get(&addr(1, 0).key()).unwrap().failures, 1);
        assert_eq!(
            restored.entries.get(&addr(1, 0).key()).unwrap().retry_at,
            320
        );
        restored.penalize(addr(2, 0).addr, 60, 201);
        assert!(restored.is_banned(&addr(2, 0).addr, 201));
    }

    #[test]
    fn successful_connection_clears_backoff_before_anchor_restart() {
        let mut book = AddressBook::new();
        let peer = addr(1, 100);
        assert!(book.add(peer, 100));
        book.failed(peer.key());
        book.attempted(peer.key(), 100);
        assert!(!book.dialable(peer.key(), 101));
        book.connected(peer.key(), 101);
        assert!(book.dialable(peer.key(), 101));
        assert_eq!(book.anchors(3, 101), vec![addr(1, 101)]);

        let saved = Snapshot::from_bytes(&book.snapshot().to_bytes()).unwrap();
        let mut restored = AddressBook::new();
        assert_eq!(restored.restore(saved, 102, |_| true), 1);
        assert!(restored.dialable(peer.key(), 102));
        assert_eq!(restored.anchors(3, 102), vec![addr(1, 101)]);
    }

    #[test]
    fn restart_anchors_use_verified_behavior_and_exclude_bans() {
        let mut book = saved_book();
        book.connected(addr(1, 0).key(), 160);
        book.connected(addr(3, 0).key(), 170);
        book.penalize(addr(1, 0).addr, 20, 180);
        book.ban(addr(3, 0).addr, 180);
        assert_eq!(book.anchors(3, 200), vec![addr(2, 150), addr(1, 160)]);
        let mut restored = AddressBook::new();
        restored.restore(book.snapshot(), 200, |_| true);
        assert_eq!(restored.anchors(2, 200), book.anchors(2, 200));
    }

    #[test]
    fn restored_books_keep_verification_under_gossip_rules() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut book = AddressBook::new();
        let added = book.restore(saved_book().snapshot(), 200, |a| a.addr != addr(3, 0).addr);
        assert_eq!(added, 2, "the policy filter drops one");
        assert!(book.verified(addr(2, 0).key(), 200));
        assert!(!book.verified(addr(1, 0).key(), 200));
        assert_eq!(book.sample(10, 200, &mut rng).len(), 1);
        assert_eq!(
            book.restore(saved_book().snapshot(), 200, |_| true),
            1,
            "known stay"
        );
        assert_eq!(
            AddressBook::new().restore(saved_book().snapshot(), 150 + MAX_AGE + 1, |_| true),
            0
        );
    }

    #[test]
    fn restored_future_verification_is_not_trusted() {
        let mut book = AddressBook::new();
        book.restore(saved_book().snapshot(), 120, |_| true);
        assert_eq!(book.len(), 3);
        assert!(
            !book.verified(addr(2, 0).key(), 120),
            "verified at 150, now is 120"
        );
    }
}
