# PoW, node synchronization, and storage review

Review date: 2026-11-16. Scope: the current working tree, including the earlier build and performance changes. The initial review was followed by fixes for S1, S2, and D1, described below. Consensus rules, validation results, wire encoding, and the database layout are unchanged.

The findings below describe the pre-fix behavior. Database distribution currently consists of validated block exchange into each node's local database; a chain snapshot protocol is not implemented.

## Implemented corrections

- **S1:** Downloaded hashes are acknowledged only after successful import. An expected orphan remains in flight; only its hash and parent hash are retained. Importing the parent triggers a fresh request for the child with a renewed deadline. This metadata stays within the 16-body download window, and synchronization cannot complete while the child remains unresolved. No large orphan-body cache is introduced.
- **S2:** Header responses must be solicited and form a contiguous hash/height sequence, including continuations and already-known headers. Invalid batches leave downloader state unmodified. The node abandons an invalid response's sync session, settles that peer's height claim, and applies its existing misbehavior penalty. Only newly queued download work or successfully imported expected blocks refresh the progress timer.
- **D1:** `GetData` deduplicates hashes and retains a bounded pending inventory per peer, preserving the existing 50,000-item wire limit. Serving performs at most 16 lookups per turn. A storage length accessor reserves capacity before decoding a block; successful writes resume pending service, with a tick fallback when another peer frees the global budget. Valid batches larger than a serving turn remain supported.
- **D1:** Outboxes account for queued and active-write messages using conservative admission charges: 384 MiB per peer and 1 GiB shared across connections in the process, alongside the existing 1,024-message cap. Charges include decoded data and serialization/framing/encryption buffers; bulk reservations leave control-message headroom. These limits are not total-process RSS limits and do not cover inbound queues or every allocation in other handlers.
- **D1:** Dropping the last outbox immediately cancels socket work and discards its backlog. Each message write also has a 120-second deadline, preventing a nonreading peer from retaining outbound reservations indefinitely.

No dependency was added. The storage accessor reads the length of the existing block value; it adds no table, index, or persisted format. Remaining findings S3, P1/P2/P3, and D2 are not implemented in this patch.

## Findings

Priorities describe operational impact. Performance findings below are based on code paths unless a measurement is explicitly identified; they are not measured speedup claims.

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| S1 | High | A child received before its parent is removed from download tracking and can be discarded without retry. Sync can then be reported complete. | Public state-machine probe and node import-path inspection. |
| S2 | High | Full batches of repeated known headers refresh the stall timer with no forward progress, keeping sync and mining paused. | Public state-machine probe and node timer/readiness inspection. |
| D1 | High | Bulk block serving limits message count, without bounding queued bytes or work after disconnect. | Request decoder, serving loop, and writer inspection; no memory-exhaustion attack executed. |
| S3 | Medium | `NotFound` is ignored, and a timed-out peer's claim is settled without an automatic cooldown retry. | Error/retry path inspection. |
| P1 | Medium | Each miner worker rebuilds and proves a coinbase after at most 32 nonce attempts. | Miner call-path inspection; throughput impact not yet measured. |
| P2 | Medium | Header operations decode complete bodies, while block validation and serving run on the node actor. | Storage/read-path and event-loop inspection. |
| D2 | Medium | Ineligible deep side branches are persisted before the fork-depth check; ancestry traversal and retained bodies are not bounded by that check. | Side-chain validation, import, and pruning-path inspection. |
| P3 | Medium | Pool templates can become stale during proving and concurrent cache misses can duplicate proving. | RPC template-path inspection. |

### S1: out-of-order bodies can be lost

Locations: `crates/runtime/src/node.rs:1271` (`on_block`), `:1126` (`start_sync`), `:1216` (`finish_sync_if_done`); `crates/p2p/src/sync.rs:185` (`on_block`).

The downloader permits 16 bodies in flight. `Node::on_block` removes a received hash from the in-flight map before `Chain::import` succeeds. If the child arrives before its parent, import returns `Orphan`. Calling `start_sync` does nothing while `sync_peer` is already set. There is no body buffer or requeue for that child.

After the parent arrives, the queues can be empty and `exhausted` true even though the child was never applied. The node then logs successful synchronization and settles the peer's claim. A subsequent announcement or reconnect may trigger recovery; this completion condition itself does not ensure that the downloaded chain was applied. TCP preserves transmission order, but a peer can choose the order in which it sends requested bodies.

Proposed correction: retain bodies in a bounded dependency buffer or requeue them, distinguish receipt from successful import, and complete sync only after all requested dependencies are resolved. Keep state application ordered and preserve the existing consensus checks. Regression coverage should deliver a valid child first, then its parent, and verify both application and the final tip.

### S2: known-header replay counts as progress

Locations: `crates/p2p/src/sync.rs:124` (`on_headers`); `crates/runtime/src/node.rs:1179` (`on_headers`), `:1533` (`mining_readiness`), `:1753` (stall detection).

The chaining check accepts a header when its parent is known, even when all 2,000 entries repeat the same known header. The batch is accepted, zero bodies are queued, and a full batch leaves `exhausted` false. The next header request can therefore use the same continuation hash repeatedly.

The node refreshes `sync_progress_at` on every accepted batch, including these zero-progress batches. No body request is in flight, so the 60-second body timeout does not help. A selected peer can repeatedly answer before the 120-second stall deadline and keep `sync_peer` set. That prevents mining and prevents another peer from supplying the active sync's headers. The existing heartbeat must still be answered, but this does not require new chain work.

Proposed correction: validate response ordering and continuation against the request, reject duplicate/non-advancing runs, and refresh the stall timer only on genuine progress. Receiving unvalidated headers alone should not be sufficient to postpone recovery indefinitely. Tests should exercise repeated known full batches, unsolicited batches, and failover to a progressing peer.

### D1: block-serving resource amplification

Locations: `crates/p2p/src/message.rs:18` (`MAX_INVENTORY`); `crates/runtime/src/node.rs:1245` (`on_get_data`), `:910` (`send`); `crates/runtime/src/net.rs:22` (`OUTBOX_CAPACITY`), `:256`, `:281` (`write_loop`).

`GetData` accepts up to 50,000 inventory entries, including duplicate block hashes. Each entry independently loads and decodes its block. A slow reader can accumulate owned block messages in an outbox that holds 1,024 messages, regardless of their size. Queue memory therefore scales with the decoded sizes of those bodies, rather than a configured byte budget. A requester can repeat an existing public block hash; it does not need to mine new blocks to cause repeated reads and allocations.

When `try_send` fails, `send` removes the peer, but `on_get_data` continues reading the remaining entries. Dropping the sender also permits the writer to drain its buffered messages; it does not immediately cancel a blocked socket write. The synchronous request handler can monopolize the node actor during this work.

Proposed correction: deduplicate inventory using a hasher suitable for adversarial input, bound per-request work, and enforce per-peer and global queued-byte budgets before loading bodies. Service large requests incrementally, stop when the peer is removed, and explicitly cancel/discard its writer backlog. Test with a slow reader and repeated stored hashes. No OOM, specific peak-RSS value, or maximum-block-size amplification was measured in this review.

### S3: incomplete missing-body recovery

Locations: `crates/runtime/src/node.rs:1038` (`NotFound` handling), `:1519` (`claims`), `:1730` (request timeout).

Matching `NotFound` responses are ignored, so recovery waits for the 60-second request timeout. A timeout resets the downloader and settles the connected peer's claim. Automatic peer selection excludes settled claims. A transient failure with only one archival peer can therefore leave the node behind until a later announcement or reconnect supplies another trigger.

Proposed correction: act immediately on matching missing-body responses, retain unresolved work, and separate cooldown/retry policy from handshake claims used to decide mining readiness. Recovery must avoid repeatedly selecting a withholding peer. Test temporary failure followed by recovery on the same connection.

### P1: repeated coinbase proving in mining

Locations: `crates/runtime/src/miner.rs:27` (`NONCES_PER_TEMPLATE`), `:57` (`assemble`), `:134` (`mine`), `:252` (`Worker::run`).

Every worker requests a template, assembles and proves a coinbase, and tries at most 32 nonces. If no nonce succeeds, the process repeats even if the parent and included transactions have not changed. Each worker independently pays the preparation cost. The wasted preparation becomes relevant when many nonce batches are needed; its share of wall time must be measured at representative difficulty.

Proposed experiment: retain an immutable prepared block while its parent, transaction selection, and timestamp policy remain usable. Share prepared work where appropriate and keep independent RandomX VMs and nonce streams. Recheck tip movement before publishing work and discard stale results. Compare assembly/proving time, hashes per second, stale-work latency, RSS, and one/multiple workers before retaining a patch. Do not change randomness, proof bytes, target rules, or cancellation behavior as an incidental optimization.

### P2: body decoding and actor serialization

Locations: `crates/storage/src/store.rs:234` (`block`), `:154` (`tip`); `crates/chain/src/validate.rs:364` (`recent_headers`); `crates/runtime/src/node.rs:1146` (`on_get_headers`), `:1184` (known-block lookup), `:730` (event loop), `:1282` (import).

Header serving loads and decodes up to 2,000 full blocks. Recent-header collection does the same for the difficulty/timestamp lookback, and several existence checks use `Store::block`. These operations allocate and parse transaction bodies when only a header or membership result is required. The current serialized header is a fixed 177-byte prefix (`crates/protocol/src/block.rs:106`).

The node actor also calls block import synchronously, including RandomX and transaction verification. More Tokio threads do not let this actor process its other events while that call is running.

| Path | Current work | Candidate work | Constraint |
| --- | --- | --- | --- |
| Serve `k` headers | Decode the sum of all `k` body sizes. | Decode `k` fixed-size header prefixes. | Preserve encoding/error behavior; storage page I/O may remain. |
| Check block presence | Deserialize a full body. | Read membership only. | Preserve corruption/error handling where required. |
| Mine `N` unsuccessful nonces on usable work | Prepare approximately once per 32 attempts. | Prepare once per actual work refresh. | Same validation and randomness requirements; measure refresh behavior. |
| Validate a block | Actor remains busy for validation and application. | Bounded CPU work followed by serialized state application. | Recheck tip/state dependencies; preserve validation outcomes and deterministic ordering. |

Start with header-only and existence accessors over the existing table, without a new on-disk index. Benchmark small and transaction-heavy blocks before adopting the change. A CPU-worker refactor needs separate state-race and backpressure tests; merely wrapping mutable chain operations in concurrent tasks would be insufficient.

### D2: side-branch retention and traversal

Locations: `crates/chain/src/validate.rs:106` (`check_side_chain_block`, persistence at `:122`); `crates/chain/src/chain.rs:141` (validation before fork checks), `:172` (`branch_to_main_chain`); `crates/storage/src/store.rs:369` (`prune_frontiers_below`).

A side-chain block passes header/PoW, transaction-root, and authorization checks and is then persisted. Only afterward does import collect the branch and reject a fork below an applicable checkpoint or beyond the reorg-depth limit. The persisted block remains available, including as ancestry for later submissions. Branch traversal also loads full bodies before enforcing the fork restriction.

Only frontier pruning is implemented; block bodies do not have a noncanonical retention quota. Main-chain block, transaction-ID, and nullifier history also grows with the chain. Invalid PoW or invalid authorization is rejected before side-chain storage, so this is not free storage for arbitrary malformed blocks.

Proposed correction: determine fork eligibility with bounded ancestry work before persistent admission where possible, then define a storage policy for ineligible noncanonical bodies. Preserve every currently eligible reorganization and serving requirement. Do not change the consensus reorg-depth/checkpoint rules or prune canonical validation state as part of this change. Measure disk growth and traversal time with valid deep branches.

### P3: stale pool templates

Location: `crates/runtime/src/jsonrpc.rs:311` (`template_for`), proving at `:323`, cache insertion/return at `:331`.

The RPC checks readiness/tip before awaiting coinbase proving and returns/caches the result without a final tip-hash check. A new block during proving can make the returned work stale. Concurrent misses can also duplicate preparation for the same work.

Proposed correction: recheck the parent hash after proving, discard stale work, and coordinate identical in-progress preparations. Test tip movement during preparation and concurrent callers. This is wasted work, not a demonstrated PoW validation bypass.

## PoW and storage behavior already present

- RandomX recomputes the committed solution and compares it with the header's target (`crates/chain/src/pow.rs:63`). Validation first checks the expected difficulty target and timestamps (`crates/chain/src/validate.rs:144`). The domain-separated input binds the nonce and the header's consensus fields (`crates/protocol/src/block.rs:114`). No concrete PoW acceptance bypass was found in these paths; this is not an exhaustive consensus audit.
- Difficulty calculation uses integer arithmetic, and fork selection compares accumulated work. Existing difficulty/target tests exercise compact encoding, bounds, timestamp clamping, and work comparisons.
- Mining currently uses light-mode RandomX with an approximately 256 MiB cache per network key and independent worker VMs sharing that cache (`crates/chain/src/pow.rs:30`, `:54`). Native `randomx_get_flags` already selects supported JIT/hardware AES and initialization CPU features (`vendor/randomx-bindings/src/flags.rs:44`; `vendor/randomx-bindings-sys/randomx/src/randomx.cpp:43`). The wrapper's comment suggesting that defaults omit JIT is stale. A full-memory dataset would be a separate memory/throughput experiment.
- Block apply and revert update their indexes/state in one redb write transaction (`crates/storage/src/store.rs:406`, `:454`). Reorganization uses a durable journal and startup recovery restores the original validated chain (`crates/chain/src/chain.rs:207`).

## What database distribution means today

Each node owns a local `chain.redb` (`crates/runtime/src/node.rs:628`). `GetHeaders`/`Headers` discover history and `GetData`/`Block` transfer bodies; the receiver validates and applies blocks locally. There is no distributed database engine, database sharding, or authenticated chain-state snapshot export/import/bootstrap protocol.

`backupwallet` backs up wallet data. The CLI's wallet scan snapshot download retrieves block material for scanning; neither mechanism distributes a validated chain-state database.

Startup checks storage schema, network genesis, and the consensus-rules digest (`crates/storage/src/store.rs:73`; `crates/chain/src/chain.rs:51`). Opening a copied raw database does not replay and revalidate all its history. Those metadata checks therefore do not authenticate a database obtained from an untrusted party.

A future snapshot design needs a defined trust/verification model, network/rules identity, a pinned height and block hash, complete state/index coverage, integrity checking, atomic installation, and a replay fallback. A commitment-tree root alone does not authenticate all nullifier/index state. Any new persisted format or validation rule requires a separate proposal under the existing project constraints.

## Validation

The follow-up patch passed these checks offline:

| Check | Result |
| --- | --- |
| Generic P2P sync unit tests | 11 passed, including atomic rejection, replay/continuation checks, and unresolved-body retry deadlines. |
| Generic storage library tests | 15 passed; 1 measurement ignored. Includes stored-size lookup and existing state/revert/frontier checks. |
| Native release runtime library tests | 100 passed, including 15 network tests for byte/count budgets, active writes, shared capacity, cancellation, and writer deadlines. |
| Native release normal node sync tests | 5 passed, including follower/payment relay, restart, peer caps, and address exchange. |
| Generic full-node adversarial regressions | 5 passed: reordered valid bodies, known-header replay, duplicate requests, oversized inventory, and incremental valid bulk service. The bulk-service regression also serves a real coinbase/proof body. |
| Workspace check, all targets | Passed. |
| Formatting and diff whitespace | Passed. |

The byte-budget tests include an actual TCP peer that does not read, and verify reservation release after cancellation and after a write deadline. They do not establish a total-process memory limit. Socket tests require loopback permission; sandbox-denied runs were rerun with that permission. Clippy was unavailable in the pinned Rust 1.90.0 toolchain, so no Clippy result is claimed.

```sh
env RUSTFLAGS='' cargo test -p p2p --lib sync::tests --locked --offline
env RUSTFLAGS='' cargo test -p storage --lib --locked --offline
env RUSTFLAGS='' cargo test -p runtime --test sync_adversarial --locked --offline -- --nocapture --test-threads=1
env CARGO_TARGET_DIR=/tmp/kryptos-build-native cargo test --release -p runtime --lib --test sync --locked --offline -- --nocapture --test-threads=1
env RUSTFLAGS='' cargo check --workspace --all-targets --locked --offline
cargo fmt --all -- --check
git diff --check
```

The original review commands and evidence are retained below for comparison:

```sh
env RUSTFLAGS='' cargo test -p p2p --lib sync::tests --locked --offline
env RUSTFLAGS='' cargo test -p chain --lib --locked --offline
env CARGO_TARGET_DIR=/tmp/kryptos-build-native cargo test --release -p runtime --test sync follower_syncs_from_miner_and_relays_a_payment --locked --offline -- --nocapture --test-threads=1
```

- Sync unit tests: **6 passed**. These cover ordered downloads, queue/request caps, gaps, timeouts, and exhaustion.
- Chain library tests: **30 passed**, including the published RandomX vectors, difficulty/target checks, and recovery after interrupted reorg phases.
- Two-node release test: **1 passed** in 48.11 seconds. The follower followed six mined blocks and relayed a payment that was mined into the sixth block. Its first sandboxed run was denied permission to bind a local socket; the same offline test passed when rerun with loopback access.
- A temporary public-API probe at `/tmp/kryptos-sync-probe` exercised S1 and S2. It used synthetic headers and simulated the child's orphan outcome; it did not run a full-node adversarial peer or validate PoW for those synthetic headers. Output:

```text
out_of_order: requested=2 child_removed=true parent_removed=true queued=0 in_flight=0 idle=true exhausted=true retries=0
known_headers: round=1 accepted=2000 newly_queued=0 queued=0 in_flight=0 exhausted=false requests_more_headers=true
known_headers: round=2 accepted=2000 newly_queued=0 queued=0 in_flight=0 exhausted=false requests_more_headers=true
known_headers: round=3 accepted=2000 newly_queued=0 queued=0 in_flight=0 exhausted=false requests_more_headers=true
```

To reproduce S1 with the public API, queue two chained unknown headers after a known parent, request both, call `on_block` for the child first, simulate its failed import, then acknowledge the parent. The state reports idle and exhausted with no retries. For S2, pass a full `MAX_HEADERS` batch repeating one known header with a known parent, then request continuation; the same batch remains accepted on subsequent rounds with zero queued bodies.

The original public probe isolated the bugs without a full adversarial node. The follow-up full-node regressions above now cover those failures. Sustained-load latency, measured peak RSS, and snapshot verification remain outside this patch. Existing storage/reorg tests were inspected for coverage; the earlier broader release-test results are recorded in `docs/build-performance.md`.

## Recommended sequence

1. Correct S1/S2 and recovery in S3, with full-node regressions for reordering, zero progress, and temporary missing bodies.
2. Bound D1's request work, queued bytes, and writer lifetime; verify both honest bulk sync and slow-reader behavior.
3. Profile P1/P2/P3 with assembly/proving vs nonce time, header decode cost, actor latency, and realistic block sizes. Retain only measured performance improvements and rerun the generic/native consistency vectors.
4. Bound side-branch admission/retention without changing reorg eligibility. Design authenticated snapshots separately if faster bootstrap is required.

S1, S2, and D1 are addressed by the follow-up patch above. The remaining sequence is unchanged; performance changes still require measurements and consistency vectors before adoption.
