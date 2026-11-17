# Block propagation measurements

The repository includes a repeatable relay measurement and a deliberately conservative interval evaluator. Run the deterministic memory transport smoke test from the repository root:

```sh
cargo test -p runtime --test propagation delayed_three_node_relay_reports_timings --locked --offline -- --nocapture
```

To save the JSON report and evaluate it:

```sh
RHOMBUS_PROPAGATION_REPORT=/tmp/rhombus-propagation.json \
  cargo test -p runtime --test propagation delayed_three_node_relay_reports_timings \
  --locked --offline -- --nocapture
python3 scripts/evaluate_block_interval.py /tmp/rhombus-propagation.json
```

The test builds a three-node `A -> B -> C` path over the memory transport and delays each application frame by 75 ms in each direction. It measures time from source block submission to the follower's accepted tip with a monotonic process clock. The report includes p50, p90, and p95 samples and records that the transport is synthetic. It does not claim public-Tor latency, majority-hashrate propagation, or stale rate under contention.

An ignored test can collect a small public-Tor result after two onion services bootstrap:

```sh
RHOMBUS_PROPAGATION_SAMPLES=20 \
RHOMBUS_PROPAGATION_REPORT=/tmp/rhombus-public-tor.json \
  cargo test -p runtime --test propagation public_tor_two_node_relay_reports_timings \
  --locked --offline -- --ignored --nocapture
```

Both nodes in that experiment run on one host, so it is still not a geographically distributed campaign. Repeat it from multiple locations, with warm and cold Tor clients, varied block sizes and proof counts, and at least two competing miners before changing a consensus interval.

The evaluator shows a simple Poisson arrival calculation for candidate intervals of 10, 30, and 60 seconds. That number is only the probability of at least one block arriving during the measured path delay under a constant-rate model. It is not an orphan-rate estimate, an attack-cost estimate, or a consensus recommendation. The mainnet target is now 300 seconds. The measurements below used the earlier 10-second target; a distributed campaign is still needed to measure p95 path delay and stale blocks while miners compete.

For an existing node, obtain the same counters and histogram snapshots with its
authenticated loopback JSON-RPC service (substitute the configured port):

```sh
curl --silent --show-error http://127.0.0.1:18443/ \
  -H "Authorization: Bearer $RPC_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"getmetrics","params":[],"id":1}'
```

`getmetrics` exposes the retained local-block counts and timing histograms through authenticated JSON-RPC. The internal Prometheus renderer names the same stale count `blocks_mined{state="stale"}`. It counts valid local blocks outside the current main chain in a bounded process history. `block_first_seen_to_import_seconds` measures only this node's first local observation through valid import, so it excludes propagation before the first observation. `block_validation_seconds` measures valid block validation and storage time. Rejected blocks and results withheld while mining readiness is lost are separate counters. Histogram buckets are cumulative with seventeen finite millisecond boundaries and a final infinity bucket; `sum_nanos` preserves submillisecond time. Peer-controlled timestamps are never used for these durations.

## Recorded local smoke run (November 16, 2026)

The [raw report](measurements/2026-11-16-memory-relay.json) and
[interval evaluation](measurements/2026-11-16-memory-interval-evaluation.json)
record an x86_64 Linux test-profile run of four sequential coinbase-only blocks.
The deterministic transport adds 75 ms per application frame in each direction;
proof verification, database work, scheduler contention and source import are measured,
not mocked.

| Path | Samples | p50 | p90 / p95 |
| --- | ---: | ---: | ---: |
| Source submission to B tip | 4 | 0.367 s | 0.372 s |
| Source submission to C tip, through B | 4 | 0.584 s | 0.591 s |

All four blocks reached both followers and none became stale. Because only one
source produced blocks sequentially, that zero does not estimate the stale rate
with competing miners. The two-hop p95 is 5.91% of a 10-second interval in this
fixture; it does not establish a safe target for the public Tor network.
No consensus interval was changed.

A separate regression constructs two same-height local solutions, imports one
directly as a side branch, resubmits it, then extends that branch until it wins.
The retained counts stay accurate through duplicate submissions and the reorg,
and an invalid target increments only the rejection counter.

## Recorded public-Tor smoke run (November 16, 2026)

The [public-Tor raw report](measurements/2026-11-16-public-tor-relay.json) and
[interval evaluation](measurements/2026-11-16-public-tor-interval-evaluation.json)
record two fresh embedded Arti services on one x86_64 Linux host. The test
completed bootstrap, the application handshake and initial header sync, then
propagated four actual coinbase-only blocks over public Tor. The entire test,
including bootstrap and local block creation, took 186.70 seconds.

| Path | Samples | p50 | p90 / p95 |
| --- | ---: | ---: | ---: |
| Source submission to follower tip over public Tor | 4 | 1.483 s | 1.778 s |

This observed p95 path consumes about 17.8% of a 10-second interval. The simple
Poisson model yields about 16.3% probability of another block arriving within
that fixed delay at a 10-second target; this is explicitly **not** an orphan-rate
measurement. All four sequential blocks were accepted and no competing miner
was active, so zero observed stales cannot validate the target interval.

These results establish that real block relay worked in this small experiment,
and justify gathering a distributed competing-miner dataset before accepting
10 seconds as a deployment target. They do not establish that 30 or 60 seconds
is optimal, nor authorize changing an existing chain's consensus parameters.
