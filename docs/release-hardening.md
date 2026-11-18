# Reorg policy, wallet backup, and efficiency changes

This development revision implements the operator's selected **50-block maximum
reorganization** policy, completes wallet backup recovery, and improves node and
miner resource use. Bootstrap peer lists intentionally remain empty; operators
continue to select peers with `--seed`, `--addnode`, or `--connect`.

## Consensus change and compatibility

Previously `main` allowed reorganization of up to 100 canonical blocks and
`test` allowed 200. Both configurations now allow reverting **at most 50**
canonical blocks from the current tip. A fork exactly 50 blocks deep remains
eligible if it passes all other checks and has strictly more cumulative work.
A fork 51 or more blocks deep is rejected regardless of its work. Checkpoint
restrictions still apply independently. The limit counts reverted canonical
blocks, not the number of incoming blocks.

At the main network's 120-second target interval, 50 blocks correspond to about
1 hour 40 minutes. Actual elapsed time varies. This is a local acceptance
boundary, not a guarantee that isolated miners agree on finality. If a partition
leaves competing branches beyond the limit, automatic reorganization cannot
reconcile them. Operators must compare independently obtained validated chain
histories and coordinate a recovery decision; never erase wallet files during
chain recovery.

This is a change to provisional launch parameters from genesis, **not a scheduled
upgrade of an existing public network**. `max_reorg_depth` and the target block
interval are included in the consensus rules digest used for database
compatibility. Peer handshakes check the genesis hash and protocol version.
Databases stamped with the previous rules are refused with `RulesMismatch`;
the implementation does not rewrite their digest or trust their historical state
under the new policy. Operators adopting the revision must back up their stopped
node/wallet, agree on the revision, and validate history into a separate fresh
chain directory using peers on the same rules. Keep the original database and
binary for rollback. No network is launched or existing database migrated by
this source change.

The LWMA uses the 120-second mainnet target and a 100-block window. The same
genesis identifies mainnet, so operators must coordinate which binaries they
run when switching from the 300-second rules.
Frontier retention covers the sum of the reorg window and anchor age so valid
anchors remain available after a permitted rollback. Eligible reorgs must still
recover atomically through the existing durable reorganization journal.

## Implementation requirements

- Reject ineligible side branches before persisting their blocks/work; traverse
  stored headers without allocating all transaction bodies. Preserve validation
  for eligible reorganizations and do not silently delete canonical data.
- Read headers directly from the existing block representation for header-only
  paths; keep full block decoding for callers needing transactions.
- Reuse prepared mining work between nonce batches while its parent and template
  remain usable. Preserve per-nonce cancellation and reject work invalidated
  during coinbase proof preparation.
- Persist a new receiving address and its separate ML-KEM key allocation in the
  same scan transaction that finds a payment to the active address. Keep older
  addresses scannable without consuming another index on repeated payments.
- Restore wallet backups only into a new file, preserving recovery/address
  metadata and rejecting incompatible or malformed backups. Existing backup
  secrets remain plaintext; encryption is a separate format/security change.

Validation must cover the reorg boundary, refusal without persistent side
effects, compatibility rejection, backup round trips and failures, and mining
cancellation/template invalidation. Timing measurements describe only the
measured host and workload; they do not establish public-Tor capacity.

## Validation

On 2026-11-18, the final combined workspace run completed with **631 passed,
13 failed and 12 ignored** across 45 unit, integration, binary and documentation
test targets. Cargo returned exit status 101; this is not a green workspace run.
All targets executed, including doctests. The ignored tests comprise four
public-Tor exercises, seven measurements and one fixed-base table generator.

```sh
CARGO_TARGET_DIR=local-test/validation-target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --workspace --locked --no-fail-fast -- --test-threads=2
```

An earlier attempt lost its compiled artifacts when the normal build directory
disappeared during testing. The final run used an isolated ignored directory;
only debug symbols were disabled, retaining the normal test optimization and
assertions. It completed without missing artifacts.

The 13 failures are confined to four runtime targets:

| Target | Passed | Failed | Failure evidence |
| --- | --- | --- | --- |
| `runtime --lib` | 119 | 9 | Eight socket tests returned `EPERM`; the signal notification test timed out. |
| `runtime --test mining` | 0 | 2 | HTTP listener socket creation returned `EPERM`. |
| `runtime --test rpc` | 0 | 1 | Local RPC listener socket creation returned `EPERM`. |
| `runtime --test walletd` | 0 | 1 | Wallet daemon listener socket creation returned `EPERM`. |

The signal timeout was reproduced separately: SIGTERM reaches the process, but
the sandbox denies `send(..., MSG_NOSIGNAL)` on Tokio's Unix wakeup socket.
Tokio records the signal and discards the failed wakeup write, leaving its driver
without readiness to broadcast it. A direct diagnostic confirmed `EPERM` for
that send and successful notification through an `os.write` control. These
failures require a rerun with socket access; no tests were skipped to hide them.
The automatic approval reviewer failed with an account/API incompatibility, so
the requested run outside the sandbox was not executed.

All 55 wallet tests passed, including two regressions added during this review:
restore rejects coin heights inconsistent with recorded block positions, and
valid legacy coins beyond the local `u64` address allocation space restore
successfully. Both cover rollback and witnesses. All ten mining-policy tests,
34 chain unit tests, 28 active chain integration tests, seven mempool tests,
storage tests, mining preparation/cancellation tests and memory-transport
sync/adversarial tests also passed.

Workspace all-target compilation, formatting, Clippy, whitespace checks, the
Tor-only source guard and independent seed vectors passed. Clippy still reports
warnings; these results are not a warning-free claim. The cached dependency
audit failed with three vulnerabilities and two unmaintained-package warnings;
see [dependency validation](dependency-maintenance.md#dependency-validation-on-2026-11-18)
for scope and remediation constraints. A fresh advisory fetch was also blocked
by the approval reviewer failure. Dependency remediation and a fresh online
audit remain release requirements.

See [crypto build vector evidence](crypto-build-vector.md),
[backup validation](wallet-backup.md), [mining measurements](mining-efficiency.md),
and [header-read measurements](storage-efficiency.md) for their tested scope.
No public network was launched, no user wallet was accessed, and no external
security audit or new public-Tor stress campaign is claimed.
