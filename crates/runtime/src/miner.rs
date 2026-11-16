//! Block templates and the mining task.

use chain::difficulty::{next_target, Sample};
use chain::params::ChainParams;
use chain::pow::RandomXPow;
use chain::target::Target;
use p2p::transport::TorStatus;
use protocol::address::RhombusAddress;
use protocol::amount::RawCoin;
use protocol::block::{empty_header, tx_root, Block, BlockHash, BlockHeader, PowSolution};
use protocol::builder::{Builder, OutputInfo};
use protocol::consensus::{next_height, BLOCK_VERSION};
use protocol::fee::block_mint;
use protocol::transaction::Transaction;
use protocol::tree_order::tree_transactions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use transaction_proof::ProvingKey;

use rand_core::{CryptoRng, RngCore};
use storage::tree::CommitmentTree;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::node::Event;
use crate::{Error, Result};

/// Nonces tried per template before asking for a fresh one.
const NONCES_PER_TEMPLATE: u32 = 32;
/// How long a worker waits before asking again when the node is not
/// ready to mine (Tor unavailable, no peers, or catching up).
const NOT_READY_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// What a miner needs to build the next block.
#[derive(Clone, Debug)]
pub struct Template {
    /// The tip header.
    pub parent: BlockHeader,
    /// Recent headers for the difficulty rule, oldest first.
    pub recent: Vec<BlockHeader>,
    /// The tree after the parent.
    pub tree: CommitmentTree,
    /// Transactions to include after the coinbase.
    pub transactions: Vec<Transaction>,
    /// Network parameters.
    pub params: ChainParams,
    /// Wall-clock time.
    pub now: u64,
}

impl Template {
    /// Builds the coinbase paying `miner` and assembles the header over
    /// it and the template's transactions, with the nonce and solution
    /// still empty. This is the block a pool grinds.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn assemble(
        &self,
        miner: &RhombusAddress,
        pk: &ProvingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(BlockHeader, Vec<Transaction>)> {
        let height = next_height(self.parent.height)?;
        let mint = self.mint()?;
        let mut coinbase = Builder::new(self.parent.commitment_root);
        coinbase.add_output(OutputInfo::new(miner.clone(), mint, None))?;
        let coinbase = coinbase.build_coinbase(pk, mint, self.params.branch_at(height), rng)?;

        let mut transactions = vec![coinbase];
        transactions.extend(self.transactions.iter().cloned());
        // The tree after the block, with commitments in transaction order.
        let draft = Block::new(
            empty_header(height, self.parent.hash(), self.parent.commitment_root),
            transactions,
        );
        let mut tree = self.tree.clone();
        let order = tree_transactions(&draft)?;
        for tx in order {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        let transactions = draft.transactions().to_vec();
        let header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: self.parent.hash(),
            height,
            timestamp: self.now.max(self.parent.timestamp.saturating_add(1)),
            commitment_root: tree.root(),
            tx_root: tx_root(transactions.iter().map(Transaction::txid)),
            target: self.next_target()?.to_compact(),
            nonce: [0; 32],
            solution: PowSolution::empty(),
        };
        Ok((header, transactions))
    }

    /// The coinbase mint: subsidy plus included transfer fees.
    pub fn mint(&self) -> Result<RawCoin> {
        Ok(block_mint(
            next_height(self.parent.height)?,
            self.transactions.iter().map(Transaction::fee),
        )?)
    }

    /// The target the next block must meet.
    ///
    /// # Errors
    /// Fails on a malformed target in the recent headers.
    pub fn next_target(&self) -> Result<Target> {
        let samples = self
            .recent
            .iter()
            .map(|h| {
                Ok(Sample {
                    timestamp: h.timestamp,
                    target: Target::from_compact(h.target)?,
                })
            })
            .collect::<core::result::Result<Vec<_>, chain::Error>>()?;
        Ok(next_target(
            &self.params,
            next_height(self.parent.height)?,
            &samples,
        ))
    }

    /// Assembles the block and mines it, trying a bounded number of
    /// nonces, and giving up early when `keep_going` says no: before the
    /// coinbase proof and before each nonce.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn mine(
        &self,
        miner: &RhombusAddress,
        pk: &ProvingKey,
        pow: &RandomXPow,
        rng: &mut (impl RngCore + CryptoRng),
        keep_going: impl Fn() -> bool,
    ) -> Result<Option<Block>> {
        if !keep_going() {
            return Ok(None);
        }
        let (mut header, transactions) = self.assemble(miner, pk, rng)?;
        if pow.mine_while(&mut header, NONCES_PER_TEMPLATE, rng, keep_going)? {
            Ok(Some(Block::new(header, transactions)))
        } else {
            Ok(None)
        }
    }
}

/// A running miner. Once stopped, workers finish the nonce they are
/// solving (seconds on the main network) and exit. They also drop a
/// template as soon as the best tip moves past its parent, since a block
/// on a stale parent could only become a side-chain block.
pub struct Miner {
    stop: Arc<AtomicBool>,
    task: JoinHandle<Result<()>>,
    /// Where coinbase rewards go.
    pub payout: RhombusAddress,
    /// Worker threads.
    pub threads: usize,
}

impl Miner {
    /// Stops the workers and waits for them.
    ///
    /// # Errors
    /// Returns a failure that stopped a worker before it was asked to.
    pub async fn stop(self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.task.await.map_err(|_| Error::Stopped)?
    }

    /// Waits for the workers without stopping them: until the node loop is
    /// gone, or a worker fails.
    ///
    /// # Errors
    /// Returns the first worker failure.
    pub async fn wait(self) -> Result<()> {
        self.task.await.map_err(|_| Error::Stopped)?
    }
}

/// Starts `threads` workers (at least one) mining to `payout` against the
/// node loop behind `events`. The proving key for the coinbase is built
/// once first, which takes a few seconds. Each worker fetches its own
/// template and mines from a random nonce, so workers explore disjoint
/// nonce ranges with overwhelming probability and their throughput adds up.
pub fn start(
    payout: RhombusAddress,
    params: ChainParams,
    threads: usize,
    events: mpsc::Sender<Event>,
    tip: watch::Receiver<BlockHash>,
) -> Miner {
    start_with_tor(payout, params, threads, events, tip, None)
}

/// Starts workers that also cancel their current work when the node's
/// embedded Tor service loses readiness. Offline nodes pass no status.
pub(crate) fn start_with_tor(
    payout: RhombusAddress,
    params: ChainParams,
    threads: usize,
    events: mpsc::Sender<Event>,
    tip: watch::Receiver<BlockHash>,
    tor_status: Option<watch::Receiver<TorStatus>>,
) -> Miner {
    let threads = threads.max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let payout_for_task = payout.clone();
    let task = tokio::spawn(async move {
        let pk = Arc::new(
            tokio::task::spawn_blocking(ProvingKey::build)
                .await
                .map_err(|_| Error::Stopped)??,
        );
        let pow = RandomXPow::new(params.randomx_key)?;
        let mut workers = Vec::with_capacity(threads);
        for _ in 0..threads {
            let worker = Worker {
                payout: payout_for_task.clone(),
                pow: pow.fork()?,
                pk: Arc::clone(&pk),
                stop: Arc::clone(&flag),
                tip: tip.clone(),
                tor_status: tor_status.clone(),
            };
            workers.push(tokio::spawn(worker.run(events.clone())));
        }
        for worker in workers {
            worker.await.map_err(|_| Error::Stopped)??;
        }
        Ok(())
    });
    Miner {
        stop,
        task,
        payout,
        threads,
    }
}

/// Whether a worker should try another nonce on a template built on
/// `parent`: it has not been stopped, `parent` is still the best tip, and
/// its embedded Tor service (if any) is ready.
fn worth_mining(
    stop: &AtomicBool,
    tip: &watch::Receiver<BlockHash>,
    parent: BlockHash,
    tor_status: Option<&watch::Receiver<TorStatus>>,
) -> bool {
    !stop.load(Ordering::Relaxed)
        && *tip.borrow() == parent
        && tor_status.is_none_or(crate::tor::service_ready)
}

/// What one worker needs.
struct Worker {
    payout: RhombusAddress,
    pow: RandomXPow,
    pk: Arc<ProvingKey>,
    stop: Arc<AtomicBool>,
    tip: watch::Receiver<BlockHash>,
    tor_status: Option<watch::Receiver<TorStatus>>,
}

impl Worker {
    /// Fetches a template, mines it on the blocking pool, submits any block
    /// found, and repeats until stopped or the node loop is gone.
    async fn run(self, events: mpsc::Sender<Event>) -> Result<()> {
        while !self.stop.load(Ordering::Relaxed) {
            let (reply, response) = oneshot::channel();
            events
                .send(Event::TemplateRequest(reply))
                .await
                .map_err(|_| Error::Stopped)?;
            let template = match response.await {
                Ok(Ok(template)) => template,
                Ok(Err(_)) => {
                    // The node logs why; mining on its tip now would only
                    // find blocks the network has already moved past.
                    tokio::time::sleep(NOT_READY_RETRY).await;
                    continue;
                }
                Err(_) => return Err(Error::Stopped),
            };
            let (payout, pow, pk) = (self.payout.clone(), self.pow.clone(), Arc::clone(&self.pk));
            let (stop, tip, parent) = (
                Arc::clone(&self.stop),
                self.tip.clone(),
                template.parent.hash(),
            );
            let tor_status = self.tor_status.clone();
            // Proving and solving are CPU-bound; run them on the blocking pool
            // so many workers use many cores without starving the runtime.
            let found = tokio::task::spawn_blocking(move || {
                let mut rng = rand::rngs::OsRng;
                template.mine(&payout, pk.as_ref(), &pow, &mut rng, || {
                    worth_mining(&stop, &tip, parent, tor_status.as_ref())
                })
            })
            .await
            .map_err(|_| Error::Stopped)??;
            if let Some(block) = found {
                events
                    .send(Event::Mined(Box::new(block)))
                    .await
                    .map_err(|_| Error::Stopped)?;
            }
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_continues_only_while_unstopped_and_on_the_best_tip() {
        let (a, b) = (
            BlockHash::from_bytes([1; 32]),
            BlockHash::from_bytes([2; 32]),
        );
        let (tip, watched) = watch::channel(a);
        let stop = AtomicBool::new(false);
        assert!(worth_mining(&stop, &watched, a, None));
        assert!(
            !worth_mining(&stop, &watched, b, None),
            "built on a stale parent"
        );
        tip.send_replace(b);
        assert!(!worth_mining(&stop, &watched, a, None), "the tip moved on");
        assert!(worth_mining(&stop, &watched, b, None));
        stop.store(true, Ordering::Relaxed);
        assert!(!worth_mining(&stop, &watched, b, None), "stopped");
    }

    #[test]
    fn active_work_waits_for_tor_and_stops_on_readiness_loss() {
        let parent = BlockHash::from_bytes([1; 32]);
        let (_tip, watched) = watch::channel(parent);
        let stop = AtomicBool::new(false);
        let (status, tor) = watch::channel(TorStatus::default());
        let can_mine = || worth_mining(&stop, &watched, parent, Some(&tor));
        assert!(!can_mine(), "bootstrap must finish before mining");
        let ready = TorStatus {
            client_ready: true,
            onion: Some(p2p::address::NetAddr::TorV3([2; 32])),
        };
        status.send_replace(TorStatus {
            onion: None,
            ..ready
        });
        assert!(!can_mine(), "the onion service must also be ready");
        status.send_replace(TorStatus {
            client_ready: false,
            ..ready
        });
        assert!(!can_mine(), "a service identity alone is insufficient");
        status.send_replace(ready);
        assert!(can_mine());
        status.send_replace(TorStatus::default());
        assert!(!can_mine(), "Tor loss cancels work even on the same tip");
        status.send_replace(ready);
        assert!(can_mine(), "recovery permits work again");
        drop(status);
        assert!(!can_mine(), "a stopped supervisor must block mining");
    }
}
