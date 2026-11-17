//! Node metrics snapshots and Prometheus text rendering.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use protocol::block::BlockHash;

use tokio::sync::{mpsc, oneshot};

use crate::node::{Event, NotReady, Request, Response};
use crate::{Error, Result};

/// Finite bucket boundaries in milliseconds. The final bucket is unbounded.
pub const BLOCK_TIMING_BUCKETS_MS: [u64; 17] = [
    1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000,
    600_000,
];
/// Maximum outstanding block hashes retained for local receive timing.
const MAX_OBSERVED_BLOCKS: usize = 2_048;

/// Fixed-memory histogram. Buckets are cumulative, including the final infinity bucket.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct TimingHistogram {
    /// Counts through each finite boundary and then through infinity.
    pub buckets: [u64; 18],
    /// Number of observations since startup.
    pub count: u64,
    /// Sum of observed durations in nanoseconds, saturating on overflow.
    pub sum_nanos: u64,
}

impl TimingHistogram {
    /// Records a monotonic elapsed duration using fixed memory.
    pub fn observe(&mut self, duration: Duration) {
        self.count = self.count.saturating_add(1);
        self.sum_nanos = self
            .sum_nanos
            .saturating_add(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX));
        for (index, count) in self.buckets.iter_mut().enumerate() {
            if BLOCK_TIMING_BUCKETS_MS
                .get(index)
                .is_none_or(|limit| duration <= Duration::from_millis(*limit))
            {
                *count = count.saturating_add(1);
            }
        }
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
        for (index, count) in self.buckets.iter().enumerate() {
            let bound = BLOCK_TIMING_BUCKETS_MS.get(index).map_or_else(
                || "+Inf".to_string(),
                |ms| format!("{}.{:03}", ms / 1_000, ms % 1_000),
            );
            let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {count}");
        }
        let seconds = self.sum_nanos / 1_000_000_000;
        let nanos = self.sum_nanos % 1_000_000_000;
        let _ = writeln!(
            out,
            "{name}_sum {seconds}.{nanos:09}\n{name}_count {}",
            self.count
        );
    }
}

/// Aggregate local block timing. Quantiles must name their measured interval;
/// neither histogram measures travel from the originating miner to this node.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct BlockTimingMetrics {
    /// First local announcement/header/body observation until valid remote import.
    pub first_seen_to_import: TimingHistogram,
    /// Time spent validating and storing valid new local or remote blocks.
    pub validation: TimingHistogram,
    /// Outstanding observations evicted at the memory bound.
    pub observation_evictions: u64,
}

/// Bounded, process-local observations using monotonic time and block hashes only.
#[derive(Default)]
pub struct BlockTelemetry {
    first_seen: HashMap<BlockHash, Instant>,
    order: VecDeque<BlockHash>,
    metrics: BlockTimingMetrics,
}

impl BlockTelemetry {
    /// Remembers the first observation only. Repeated announcements cannot reset it.
    pub fn observe(&mut self, hash: BlockHash, now: Instant) {
        if self.first_seen.contains_key(&hash) {
            return;
        }
        if self.order.len() >= MAX_OBSERVED_BLOCKS {
            if let Some(oldest) = self.order.pop_front() {
                self.first_seen.remove(&oldest);
                self.metrics.observation_evictions =
                    self.metrics.observation_evictions.saturating_add(1);
            }
        }
        self.order.push_back(hash);
        self.first_seen.insert(hash, now);
    }

    /// Finishes an import attempt. `valid_new` excludes duplicates and rejected
    /// imports. Validation timing includes local blocks; first-seen timing only
    /// includes remote blocks with a retained observation.
    pub fn imported(
        &mut self,
        hash: BlockHash,
        remote: bool,
        valid_new: bool,
        validation_elapsed: Duration,
        now: Instant,
    ) {
        let first_seen = self.first_seen.remove(&hash);
        self.order.retain(|queued| *queued != hash);
        if !valid_new {
            return;
        }
        self.metrics.validation.observe(validation_elapsed);
        if remote {
            if let Some(first_seen) = first_seen {
                self.metrics
                    .first_seen_to_import
                    .observe(now.saturating_duration_since(first_seen));
            }
        }
    }

    /// Fixed-memory histogram snapshot suitable for a metrics response.
    pub fn snapshot(&self) -> BlockTimingMetrics {
        self.metrics.clone()
    }
}

/// A snapshot of what the node is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Tip height.
    pub height: u32,
    /// Ready inbound peers.
    pub peers_inbound: usize,
    /// Ready outbound peers.
    pub peers_outbound: usize,
    /// Pooled transactions.
    pub mempool: usize,
    /// Valid, distinct local blocks retained in the bounded mining history.
    /// Includes blocks first imported directly onto a side branch.
    pub blocks_mined: usize,
    /// Of those, the ones in the main chain now; the rest went stale.
    pub blocks_mined_in_chain: usize,
    /// Retained local blocks outside the current main chain, including direct side branches.
    pub blocks_mined_stale: usize,
    /// Local block submissions rejected by validation since startup.
    pub blocks_mined_rejected: u64,
    /// Local results withheld because mining readiness was lost since startup.
    pub blocks_mined_blocked: u64,
    /// Monotonic local receive/import timing; not end-to-end network propagation.
    pub block_timing: BlockTimingMetrics,
    /// Compact blocks awaiting transactions.
    pub pending_compact_blocks: usize,
    /// Seconds since the node started.
    pub uptime_seconds: u64,
    /// Why the node would refuse mining work now, or `None` if it would
    /// hand it out.
    pub mining_waits: Option<NotReady>,
}

/// Renders the snapshot in the Prometheus text format.
#[must_use]
pub fn render(m: &Metrics) -> String {
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, value: String| {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{value}");
    };
    gauge(
        "height",
        "Height of the chain tip.",
        format!("height {}", m.height),
    );
    gauge(
        "peers",
        "Connected peers past the handshake, by direction.",
        format!(
            "peers{{direction=\"inbound\"}} {}\npeers{{direction=\"outbound\"}} {}",
            m.peers_inbound, m.peers_outbound
        ),
    );
    gauge(
        "mempool_transactions",
        "Transactions in the mempool.",
        format!("mempool_transactions {}", m.mempool),
    );
    gauge(
        "blocks_mined",
        "Valid local blocks retained in bounded history, including direct side branches; state reflects the current chain.",
        format!(
            "blocks_mined{{state=\"found\"}} {}\nblocks_mined{{state=\"in_chain\"}} {}\nblocks_mined{{state=\"stale\"}} {}",
            m.blocks_mined, m.blocks_mined_in_chain, m.blocks_mined_stale
        ),
    );
    gauge(
        "pending_compact_blocks",
        "Compact blocks waiting for transactions.",
        format!("pending_compact_blocks {}", m.pending_compact_blocks),
    );
    gauge(
        "uptime_seconds",
        "Seconds since the node started.",
        format!("uptime_seconds {}", m.uptime_seconds),
    );
    gauge(
        "mining_ready",
        "1 if the node is currently ready to hand mining work to miners, else 0.",
        format!("mining_ready {}", u8::from(m.mining_waits.is_none())),
    );
    let _ = writeln!(out, "# HELP local_mining_rejected_total Local blocks rejected by validation.\n# TYPE local_mining_rejected_total counter\nlocal_mining_rejected_total {}", m.blocks_mined_rejected);
    let _ = writeln!(out, "# HELP local_mining_blocked_total Local results withheld while mining was not ready.\n# TYPE local_mining_blocked_total counter\nlocal_mining_blocked_total {}", m.blocks_mined_blocked);
    m.block_timing.first_seen_to_import.render(
        &mut out,
        "block_first_seen_to_import_seconds",
        "Time from this node first observing a remote block hash to completing its valid import; excludes travel before first observation.",
    );
    m.block_timing.validation.render(
        &mut out,
        "block_validation_seconds",
        "Time in chain import for valid new blocks, including proof verification and storage; both local and remote blocks.",
    );
    let _ = writeln!(out, "# HELP block_observation_evictions_total Unfinished block observations evicted from bounded timing state.\n# TYPE block_observation_evictions_total counter\nblock_observation_evictions_total {}", m.block_timing.observation_evictions);
    out
}

/// Asks the node loop for a snapshot.
///
/// # Errors
/// Returns [`Error::Stopped`] if the loop is gone.
pub async fn snapshot(events: &mpsc::Sender<Event>) -> Result<Metrics> {
    let (reply, response) = oneshot::channel();
    events
        .send(Event::Rpc {
            request: Request::Metrics,
            reply,
        })
        .await
        .map_err(|_| Error::Stopped)?;
    match response.await.map_err(|_| Error::Stopped)? {
        Response::Metrics(metrics) => Ok(*metrics),
        Response::Failed(reason) => Err(Error::Argument(reason)),
        _ => Err(Error::Stopped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_follows_the_text_format() {
        let text = render(&Metrics {
            height: 7,
            peers_inbound: 1,
            peers_outbound: 2,
            mempool: 3,
            blocks_mined: 5,
            blocks_mined_in_chain: 4,
            blocks_mined_stale: 1,
            blocks_mined_rejected: 2,
            blocks_mined_blocked: 3,
            block_timing: BlockTimingMetrics::default(),
            pending_compact_blocks: 0,
            uptime_seconds: 60,
            mining_waits: Some(NotReady::Syncing),
        });
        for line in [
            "# TYPE height gauge",
            "height 7",
            "peers{direction=\"inbound\"} 1",
            "peers{direction=\"outbound\"} 2",
            "mempool_transactions 3",
            "blocks_mined{state=\"found\"} 5",
            "blocks_mined{state=\"in_chain\"} 4",
            "blocks_mined{state=\"stale\"} 1",
            "local_mining_rejected_total 2",
            "local_mining_blocked_total 3",
            "block_validation_seconds_count 0",
            "block_first_seen_to_import_seconds_bucket{le=\"+Inf\"} 0",
            "pending_compact_blocks 0",
            "uptime_seconds 60",
            "mining_ready 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn histogram_boundaries_are_cumulative_and_preserve_submillisecond_samples() {
        let mut histogram = TimingHistogram::default();
        histogram.observe(Duration::from_micros(500));
        histogram.observe(Duration::from_millis(5));
        histogram.observe(Duration::from_secs(700));
        assert_eq!(histogram.count, 3);
        assert_eq!(histogram.buckets[0], 1);
        assert_eq!(histogram.buckets[1], 2);
        assert_eq!(histogram.buckets[16], 2);
        assert_eq!(histogram.buckets[17], 3);
        let mut text = String::new();
        histogram.render(&mut text, "duration_seconds", "test");
        assert!(text.contains("duration_seconds_sum 700.005500000\n"));
        assert!(text.contains("duration_seconds_bucket{le=\"0.005\"} 2\n"));
    }

    #[test]
    fn first_observation_is_preserved_and_duplicates_do_not_inflate_timing() {
        let start = Instant::now();
        let hash = BlockHash::from_bytes([1; 32]);
        let mut telemetry = BlockTelemetry::default();
        telemetry.observe(hash, start);
        telemetry.observe(hash, start + Duration::from_millis(80));
        telemetry.imported(
            hash,
            true,
            true,
            Duration::from_millis(10),
            start + Duration::from_millis(100),
        );
        assert_eq!(
            telemetry.snapshot().first_seen_to_import.sum_nanos,
            100_000_000
        );
        telemetry.imported(
            hash,
            true,
            false,
            Duration::from_millis(10),
            start + Duration::from_millis(200),
        );
        assert_eq!(telemetry.snapshot().validation.count, 1);
        assert!(telemetry.first_seen.is_empty());
        assert!(telemetry.order.is_empty());
    }

    #[test]
    fn observations_are_bounded_and_local_blocks_only_count_validation() {
        let start = Instant::now();
        let mut telemetry = BlockTelemetry::default();
        for number in 0..=MAX_OBSERVED_BLOCKS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(number as u64).to_le_bytes());
            telemetry.observe(BlockHash::from_bytes(bytes), start);
        }
        assert_eq!(telemetry.first_seen.len(), MAX_OBSERVED_BLOCKS);
        assert_eq!(telemetry.order.len(), MAX_OBSERVED_BLOCKS);
        assert_eq!(telemetry.snapshot().observation_evictions, 1);
        telemetry.imported(
            BlockHash::from_bytes([9; 32]),
            false,
            true,
            Duration::from_millis(2),
            start,
        );
        assert_eq!(telemetry.snapshot().validation.count, 1);
        assert_eq!(telemetry.snapshot().first_seen_to_import.count, 0);
    }
}
