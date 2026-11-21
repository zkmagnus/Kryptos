# Testnet genesis checkpoint correction

Validation date: November 21, 2026 (Asia/Jakarta).

## Current status: full workspace passed

After all corrections described below, a new complete run of

```sh
cargo test --workspace --locked --offline --no-fail-fast -- --test-threads=2
```

finished with exit status **0**: **700 passed, 0 failed, 12 ignored** across
46 unit, integration, binary, and documentation result groups. This includes
the checkpoint regressions, deterministic crypto vector, adversarial sync,
parallel sync, node/wallet RPC, mining, storage, backup, and recovery tests.

Whitespace checks, targeted Rust formatting for all changed Rust files, and
the Tor-only source guard also passed. The 12 ignored tests remain outside
this validation; public-Tor exercises and measurements were not enabled.

## Checkpoint correction

The configured height-zero testnet checkpoint still contained
`c797b003167b16caba242e3d1c33209b0103dbefe2bfa7cc7b82033c8f214a06`,
which did not match the deterministic genesis produced by the current v1-reset
parameters. A new regression test reproduced the mismatch before correction.
The checkpoint now contains the generated hash
`6e5e4baba63b900ab9471880de8ecee013bccc110394395a50b353019ec04df6`.

The genesis generator, timestamp, and checkpoint enforcement remain unchanged.
The regression checks the configured genesis hash, state root, height, and zero
chain work. Existing databases stamped with the previous consensus rules digest
may be refused: this change does not migrate or rewrite existing databases.
No operator databases were opened or deleted.

The broader test run also exposed four stale synthetic chain fixtures which
did not commit to their parents' header-history frontiers. The fixtures now
populate the required history roots; production validation was not relaxed.

## Historical results before the final workspace run

### Targeted reruns after the checkpoint correction

- `cargo test --offline --locked -p chain --lib`: 47 passed.
- `cargo test --offline --locked -p chain --test chain a_store_with_history_but_no_rules_digest_is_refused`:
  1 passed.
- `cargo test --offline --locked -p runtime --lib --test mining --test rpc --test walletd --no-fail-fast -- --test-threads=2`:
  139 runtime unit tests, 2 mining tests, 1 RPC test, and 1 wallet-daemon test passed,
  with no failures. These targets include all 13 failures listed in the
  November 18 release-hardening report.
- Targeted Rust formatting, whitespace checks, and the Tor-only source guard passed.

The workspace run was started before the synthetic-fixture corrections, so its
initial four fixture failures must be read alongside the successful reruns above.
It also found a separate failure in `crypto --test build_consistency`:
`deterministic_crypto_build_vector` produces
`913080149e20a8cfee83882726b90abb661c4ebbd6a710f60d9790c548da3de1`
instead of its recorded
`e1081cf184e5f362183188e288ffcf789ac426b22059076f062b58d3f4f37eaf`.
At this stage the expected vector was still unchanged. Its cause and fix are
documented in the follow-up below. These tests are not an independent
cryptographic audit.

### Initial workspace result

The completed workspace command was:

```sh
cargo test --workspace --locked --offline --no-fail-fast -- --test-threads=2
```

It recorded **693 passed, 7 failed, 12 ignored** across 46 result groups and
returned exit status 101. Four failures were the synthetic chain fixtures
corrected during that run and subsequently verified by the successful reruns.
The remaining three failures are:

- `crypto --test build_consistency`: deterministic crypto vector mismatch,
  as described above.
- `runtime --test sync_adversarial`:
  `child_before_parent_is_requested_again_and_applied_before_sync_finishes`
  timed out waiting for a peer message.
- `runtime --test sync_parallel`:
  `independent_body_windows_survive_a_helper_missing_its_blocks` stopped at
  height 2 while expecting height 4. A standalone rerun also failed.

These three failures were resolved before the final workspace run. Default
ignored tests were left ignored, including public-Tor exercises and measurements.

### Follow-up resolution — November 21, 2026

The three failures above were traced to stale test expectations:

- The crypto fixture had not followed commit `97e66eba`'s rename of two
  curve domains and the synthetic signed message. Restoring exactly those
  three strings in an isolated copy reproduced the former expected digest.
  The current digest now passes in both native and portable builds; see
  [the comparison evidence](crypto-build-vector.md#kryptos-rename-vector-correction--november-21-2026).
- The adversarial test expected an out-of-order child body to be downloaded
  again. The current implementation quarantines it and validates it after
  the parent. The test now requires reaching the exact child tip without
  another child download and still requires zero peer misbehavior.
- The parallel test treated a Pong as completion of background validation.
  It now waits, with the existing bounded deadline, for the exact expected
  height, hash, and non-syncing status. Its checks for disjoint peer request
  windows, NotFound release, and exact reassignment remain intact.

No production crypto or synchronization code was changed for these findings.
The follow-up reruns passed 8 adversarial tests and 1 parallel test.
The deterministic crypto vector passed once per native/portable build, with
the timing measurement left unselected. Formatting and whitespace checks passed.

All seven failures passed in targeted reruns and in the subsequent full workspace
run summarized above.

## Public Tor follow-up — November 21, 2026

Three explicitly selected real-network tests subsequently passed outside the
restricted sandbox, each with fresh temporary state:

- `cargo test --locked --offline -p runtime --test tor_embedded two_embedded_nodes_connect_using_addnode_over_real_tor -- --ignored --nocapture`:
  1 passed, 326.56 seconds; two embedded nodes completed their onion handshake.
- `cargo test --locked --offline -p runtime --test rpc_real_tor --test propagation -- --ignored --nocapture`:
  propagation 1 passed in 171.00 seconds; RPC 1 passed in 90.01 seconds.
  These cover block relay and authenticated RPC full/light wallet reads,
  idle reconnect, and clean reopen. The combined log is locally available at
  `/tmp/kryptos-public-tor-release.log` (not a committed artifact).
- The embedded-wallet local HTTP RPC regression also passed in isolation
  (1 passed, 6.69 seconds).

The sandbox attempt failed before Tor bootstrap because its root directory
ownership was rejected by Arti. The successful external run retained Arti's
permission checks. The two-node run logged circuit retries and state-flush
errors during teardown despite passing its handshake assertion; this should
be investigated separately and is not evidence of clean Tor-state persistence.

These are additional targeted runs, not a replacement full-workspace run.
They cover three of the previously ignored tests; the other ignored tests,
including the separate p2p real-Tor test and measurements, remain unvalidated
here. Public-release readiness is still blocked by the fresh dependency audit:
see [dependency maintenance](dependency-maintenance.md#fresh-online-audit-on-2026-11-21).

## Isolated mainnet-parameter Tor relay — November 21, 2026

`cargo test --locked --offline -p runtime --test propagation public_tor_mainnet_two_node_relay_reports_timings -- --ignored --nocapture`
passed (1 test, 77.49 seconds). Both temporary nodes explicitly selected
`Network::Main`; no existing node or wallet databases were used. Four sequential
coinbase-only blocks were proved, mined, accepted and relayed over public Tor.
The source recorded four valid local blocks and zero stale local blocks.
Submission-to-follower-tip samples were 1.510849, 1.810956, 2.206256 and
2.642214 seconds (sorted); the configured mainnet target is 120 seconds.

This is a same-host, two-node isolated chain with no competing miners or user
transactions. It does not measure a geographically distributed mainnet,
transaction throughput, sustained production block intervals, or adversarial
hashrate. Bootstrap mining and a zero mining-readiness delay are explicitly
selected in the fixture. The existing test-network fixture is preserved as a
separate wrapper around the same relay scenario.

The subsequent full workspace run (`cargo test --workspace --locked --offline
--no-fail-fast -- --test-threads=2`) exited successfully: **701 passed, 0 failed, 13 ignored**, across 46 result groups.
The new public-Tor mainnet test is ignored in this default run and passed
separately as recorded above. Full-run log: `/tmp/kryptos-mainnet-readiness.log`.

## Wallet birthday/frontier recheck — November 21, 2026

The latest follow-up reviewed birthday bootstrap, missing and noncanonical
frontier recovery, address scan bounds, backups, and checkpoint RPC reconnects.
Two defects were corrected:

- Rolling back now lowers allocated address birthdays in the same transaction.
  An address shared near the old tip can receive on an earlier replacement
  block; its old scan bound must not hide that payment. The regression covers
  full and compact scans, cached scan keys, an empty imported frontier, and
  reopening the wallet.
- `scancheckpoint` is classified as a read-only RPC, permitting a dropped partial
  reply to reconnect and authenticate again. The transport regression checks
  the complete serialized header/frontier response after reconnect.

An additional sync regression verifies that replacing an imported base or
moving the node tip below it clears the old frontier and replays from genesis
in both full and compact modes, downloading before private scanning.

The final command exited with status **0**:

```sh
cargo test --locked --offline -p wallet -p runtime --lib --no-fail-fast -- --test-threads=2
```

It recorded **195 passed, 0 failed**: 143 runtime and 52 wallet tests.
Log: `/tmp/kryptos-frontier-final-recheck.log`. The earlier combined run also
passed 15 integration tests: mining (2), RPC (1), wallet daemon (1), adversarial
sync (10), and parallel sync (1). That earlier run ended with a wallet
permission-test failure because a concurrent rebuild replaced the executable
the test attempted to restart. The final run above passed that test with no
build changes during execution. Earlier log: `/tmp/kryptos-last-work-recheck.log`.

Workspace all-target compilation, Clippy, Rust formatting, whitespace checks,
the Tor-only source guard, and independent seed-vector verification passed.
Clippy continues to emit existing warnings. Tests requiring loopback listeners
and process signals ran outside the restricted sandbox. This was a targeted
wallet/runtime recheck; the full workspace and public-Tor results above remain
separate runs.
