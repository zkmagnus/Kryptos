//! RandomX proof-of-work verification and nonce search.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use protocol::block::{BlockHeader, PowSolution};
use rand_core::{CryptoRng, RngCore};
use randomx_bindings::{RandomxCache, RandomxFlags, RandomxVm};

use crate::target::Target;
use crate::{Error, Result};

static CACHES: OnceLock<Mutex<HashMap<&'static [u8], &'static RandomxCache>>> = OnceLock::new();

/// A RandomX VM for one network key.
///
/// Clones share a VM behind a mutex. Miner workers use [`Self::fork`] to
/// create independent VMs and hash in parallel, sharing the initialized cache.
#[derive(Clone)]
pub struct RandomXPow {
    cache: &'static RandomxCache,
    vm: Arc<Mutex<RandomxVm<'static, RandomxCache>>>,
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
        })
    }

    /// Checks the committed RandomX hash and its target.
    pub fn check(&self, header: &BlockHeader) -> Result<()> {
        let hash = self.hash(&header.pow_input())?;
        if header.solution.as_bytes() != &hash {
            return Err(Error::InvalidHeader("RandomX hash mismatch"));
        }
        if Target::from_compact(header.target)?.is_met_by_hash(&hash) {
            Ok(())
        } else {
            Err(Error::InvalidHeader(
                "RandomX hash does not meet the target",
            ))
        }
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
        let vm = self
            .vm
            .lock()
            .map_err(|_| Error::InvalidHeader("RandomX VM lock poisoned"))?;
        Ok(vm.hash(input))
    }
}
