//! Node metrics snapshots and Prometheus text rendering.

use std::fmt::Write as _;

use tokio::sync::{mpsc, oneshot};

use crate::node::{Event, NotReady, Request, Response};
use crate::{Error, Result};

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
    /// Blocks this node's miner found since it started.
    pub blocks_mined: usize,
    /// Of those, the ones in the main chain now; the rest went stale.
    pub blocks_mined_in_chain: usize,
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
        "Blocks this node found since it started, and how many are in the main chain now.",
        format!(
            "blocks_mined{{state=\"found\"}} {}\nblocks_mined{{state=\"in_chain\"}} {}",
            m.blocks_mined, m.blocks_mined_in_chain
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
            "pending_compact_blocks 0",
            "uptime_seconds 60",
            "mining_ready 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
        assert!(text.ends_with('\n'));
    }
}
