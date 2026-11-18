//! RandomX proof-of-work verification and nonce search.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use protocol::block::{BlockHeader, PowSolution};
use rand_core::{CryptoRng, RngCore};
use randomx_bindings::{RandomxCache, RandomxFlags, RandomxVm};

use crate::target::Target;
use crate::{Error, Result};

static CACHES: OnceLock<Mutex<HashMap<&'static [u8], &'static RandomxCache>>> = OnceLock::new();

/// Keep the successful-header cache bounded independently of sync duration.
const MAX_VERIFIED_HEADERS: usize = 4_096;

/// FIFO cache of complete headers whose `RandomX` proof was checked successfully.
#[derive(Default)]
struct VerifiedHeaders {
    hashes: HashSet<protocol::block::BlockHash>,
    order: VecDeque<protocol::block::BlockHash>,
}

impl VerifiedHeaders {
    fn contains(&self, hash: &protocol::block::BlockHash) -> bool {
        self.hashes.contains(hash)
    }

    fn insert(&mut self, hash: protocol::block::BlockHash) {
        if !self.hashes.insert(hash) {
            return;
        }
        self.order.push_back(hash);
        if self.order.len() > MAX_VERIFIED_HEADERS {
            if let Some(oldest) = self.order.pop_front() {
                self.hashes.remove(&oldest);
            }
        }
    }
}

/// A `RandomX` VM for one network key, with a bounded cache of successful
/// complete-header checks so headers-first sync can reuse work at block import.
///
/// Clones share a VM behind a mutex. Miner workers use [`Self::fork`] to
/// create independent VMs and hash in parallel, sharing the initialized cache.
#[derive(Clone)]
pub struct RandomXPow {
    cache: &'static RandomxCache,
    vm: Arc<Mutex<RandomxVm<'static, RandomxCache>>>,
    /// Shared by VM clones/forks so sync verification can be reused at import.
    verified: Arc<Mutex<VerifiedHeaders>>,
    #[cfg(test)]
    hash_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl RandomXPow {
    /// Initializes light-mode RandomX with the network's fixed key.
    ///
    /// The cache uses about 256 MiB per distinct network key and is shared
    /// across VMs for that network.
    pub fn new(key: &'static [u8]) -> Result<Self> {
        let flags = RandomxFlags::default();
        let caches = CACHES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut caches = caches
            .lock()
            .map_err(|_| Error::InvalidHeader("RandomX cache lock poisoned"))?;
        let cache = if let Some(cache) = caches.get(key) {
            *cache
        } else {
            let cache: &'static RandomxCache = Box::leak(Box::new(RandomxCache::new(flags, key)?));
            caches.insert(key, cache);
            cache
        };
        drop(caches);
        let vm = RandomxVm::new(flags, cache)?;
        Ok(Self {
            cache,
            vm: Arc::new(Mutex::new(vm)),
            verified: Arc::new(Mutex::new(VerifiedHeaders::default())),
            #[cfg(test)]
            hash_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Returns an independent VM sharing the initialized network cache.
    ///
    /// This is intended for miner workers that must hash concurrently.
    pub fn fork(&self) -> Result<Self> {
        let vm = RandomxVm::new(RandomxFlags::default(), self.cache)?;
        Ok(Self {
            cache: self.cache,
            vm: Arc::new(Mutex::new(vm)),
            verified: Arc::clone(&self.verified),
            #[cfg(test)]
            hash_calls: Arc::clone(&self.hash_calls),
        })
    }

    /// Checks the committed RandomX hash and its target.
    pub fn check(&self, header: &BlockHeader) -> Result<()> {
        let target = Target::from_compact(header.target)?;
        let header_hash = header.hash();
        if self
            .verified
            .lock()
            .map_err(|_| Error::InvalidHeader("PoW verification cache lock poisoned"))?
            .contains(&header_hash)
        {
            // The complete serialized header (including nonce, solution and
            // target) is the cache key. Recheck the inexpensive target relation
            // on every call; only the RandomX computation is skipped.
            return if target.is_met_by_hash(header.solution.as_bytes()) {
                Ok(())
            } else {
                Err(Error::InvalidHeader(
                    "RandomX hash does not meet the target",
                ))
            };
        }
        let hash = self.hash(&header.pow_input())?;
        if header.solution.as_bytes() != &hash {
            return Err(Error::InvalidHeader("RandomX hash mismatch"));
        }
        if !target.is_met_by_hash(&hash) {
            return Err(Error::InvalidHeader(
                "RandomX hash does not meet the target",
            ));
        }
        self.remember_verified_header(header_hash)?;
        Ok(())
    }

    /// Hashes the current header and installs the result if it meets target.
    pub fn try_nonce(&self, header: &mut BlockHeader) -> Result<bool> {
        let hash = self.hash(&header.pow_input())?;
        if Target::from_compact(header.target)?.is_met_by_hash(&hash) {
            header.solution = PowSolution::from_bytes(hash);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remember_verified_header(&self, hash: protocol::block::BlockHash) -> Result<()> {
        self.verified
            .lock()
            .map_err(|_| Error::InvalidHeader("PoW verification cache lock poisoned"))?
            .insert(hash);
        Ok(())
    }

    /// Mines `header` by trying random nonces, up to `max_nonces` of them.
    pub fn mine(
        &self,
        header: &mut BlockHeader,
        max_nonces: u32,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<bool> {
        self.mine_while(header, max_nonces, rng, || true)
    }

    /// Mines with a cancellation check before each nonce.
    pub fn mine_while(
        &self,
        header: &mut BlockHeader,
        max_nonces: u32,
        rng: &mut (impl RngCore + CryptoRng),
        keep_going: impl Fn() -> bool,
    ) -> Result<bool> {
        for _ in 0..max_nonces {
            if !keep_going() {
                return Ok(false);
            }
            rng.fill_bytes(&mut header.nonce);
            if self.try_nonce(header)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn hash(&self, input: &[u8]) -> Result<[u8; 32]> {
        #[cfg(test)]
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let vm = self
            .vm
            .lock()
            .map_err(|_| Error::InvalidHeader("RandomX VM lock poisoned"))?;
        Ok(vm.hash(input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::pallas;
    use protocol::block::{empty_header, BlockHash};
    use protocol::transaction::Anchor;

    fn easy_header() -> BlockHeader {
        let mut header = empty_header(
            1,
            BlockHash::ZERO,
            Anchor::from_base(pallas::Base::from(1u64)),
        );
        header.target = 0x207f_ffff;
        header
    }

    #[test]
    fn caches_only_successful_exact_header_checks_across_pow_forks() {
        let pow = RandomXPow::new(b"Rhombus PoW cache test key").unwrap();
        let fork = pow.fork().unwrap();
        let mut header = easy_header();
        let mut found = false;
        for nonce in 0..128u32 {
            header.nonce = [0; 32];
            header.nonce[..4].copy_from_slice(&nonce.to_le_bytes());
            if pow.try_nonce(&mut header).unwrap() {
                found = true;
                break;
            }
        }
        assert!(found, "the deliberately easy test target should be met");

        let mined_calls = pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(mined_calls > 0, "mining must hash its candidate nonces");
        pow.hash_calls
            .store(0, std::sync::atomic::Ordering::Relaxed);
        pow.check(&header).unwrap();
        let checked_calls = 1;
        assert_eq!(
            pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed),
            checked_calls,
            "the first successful header check computes RandomX once"
        );
        fork.check(&header).unwrap();
        assert_eq!(
            pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed),
            checked_calls,
            "VM forks share verified-header results"
        );

        let mut changed = header.clone();
        changed.timestamp = changed.timestamp.saturating_add(1);
        assert!(fork.check(&changed).is_err());
        assert_eq!(
            pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed),
            checked_calls.saturating_add(1),
            "a changed header must be hashed and cannot inherit the old result"
        );

        let mut invalid = header;
        invalid.nonce[0] ^= 1;
        invalid.solution = PowSolution::empty();
        let before = pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(pow.check(&invalid).is_err());
        assert!(pow.check(&invalid).is_err());
        assert_eq!(
            pow.hash_calls.load(std::sync::atomic::Ordering::Relaxed),
            before.saturating_add(2),
            "failed proof checks must not be cached"
        );
    }

    #[test]
    fn verified_header_cache_evicts_old_entries_at_its_fixed_bound() {
        let mut cache = VerifiedHeaders::default();
        let first = BlockHash::from_bytes([0; 32]);
        cache.insert(first);
        for index in 1..=MAX_VERIFIED_HEADERS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            cache.insert(BlockHash::from_bytes(bytes));
        }
        assert!(!cache.contains(&first));
        let mut newest = [0; 32];
        newest[..8].copy_from_slice(&u64::try_from(MAX_VERIFIED_HEADERS).unwrap().to_le_bytes());
        assert!(cache.contains(&BlockHash::from_bytes(newest)));
        assert_eq!(cache.hashes.len(), MAX_VERIFIED_HEADERS);
        assert_eq!(cache.order.len(), MAX_VERIFIED_HEADERS);
    }

    #[test]
    fn native_bindings_match_the_published_randomx_vectors() {
        // RandomX upstream vectors test_a/test_b in the vendored
        // randomx/src/tests/tests.cpp. These exercise the generated FFI and
        // native library together, independently of Rhombus header encoding.
        let pow = RandomXPow::new(b"test key 000").unwrap();
        for (input, expected) in [
            (
                b"This is a test".as_slice(),
                "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
            ),
            (
                b"Lorem ipsum dolor sit amet".as_slice(),
                "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
            ),
        ] {
            assert_eq!(
                crypto::encoding::to_hex(&pow.hash(input).unwrap()),
                expected
            );
        }
    }
}
