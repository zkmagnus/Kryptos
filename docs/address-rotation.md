# Wallet receive and change address rotation

The wallet tracks a persistent current receive address separately from its
historical default address. A current address remains stable while unused, and a
new diversified address is selected after the current one receives a scanned
payment or the wallet prepares a new outgoing transaction. Previously published
addresses remain valid and continue to be scanned.

This policy changes local wallet allocation and transaction construction. It does
not change address encoding, key derivation, transaction validity, proof rules,
consensus, or network transport. The separate ML-KEM keys used by new diversified
addresses are described in [the derivation design](diversified-ml-kem-addresses.md).

## Receive behavior

The wallet stores the index of its current receive address. Asking for that
address repeatedly returns the same value while it is unused. When a full or
compact scan detects a payment to it, the scanner invalidates that selection in
the same database transaction that records the received coins. The next request
for a receive address allocates and persists a fresh index before returning it.
This lazy allocation avoids creating an address during every scan iteration.
`getwalletinfo` also requests the current selection, so its first call after
invalidation can allocate an address; repeated polls return the persisted value.

Receipt detection is tied to the current address being used, not to an exact
counter of incoming transactions. Compact scan data does not expose the same
transaction boundaries as a full block scan. Multiple outputs to the current
address therefore invalidate it once; they do not allocate an address for each
output. Receiving another payment at an older address continues to credit the
wallet and does not invalidate an unrelated unused current address.

Rotating the current address cannot change an address already copied by a sender.
A sender can continue paying an older address. Share the newly selected receive
address for future payments when rotation is desired. Historical receipt records
retain the actual address used; they are not relabeled to the latest selection.

Manual `getnewaddress` allocation selects the new address as current, even when
the previous current address has not been used. Existing address labels and old
address encodings remain available.

## Send and change behavior

An outgoing payment still uses the recipient address supplied by the caller.
The sender cannot replace that destination with another address belonging to the
recipient. If the transaction has change, the wallet reserves a fresh diversified
address for the change output instead of returning it to index zero. Preparing a
new outgoing transaction also invalidates the current receive selection, so the
next receive-address request obtains another fresh address.

Address reservation is committed before expensive proof construction. This makes
allocation durable across crashes and ensures scanning covers the change key
before the transaction can be broadcast. A failed or interrupted proof may leave
an unused reserved index; the wallet must not rewind allocation to fill that gap.
A separately rebuilt transaction may reserve another change address. Rebroadcast
of already saved transaction bytes does not build a new transaction and does not
allocate another address.

A chain reorganization may roll back coins and transaction status, but it does
not rewind address allocation or reactivate an already invalidated receive
selection. Replaying the chain must not recycle addresses that may have been
published before the reorganization.

## Wallet RPC and CLI

| Entry point | Result |
| --- | --- |
| `getreceiveaddress` | `{ "index": <number or null>, "address": <string or null>, "exhausted": <bool> }`; obtains the persisted current selection, allocating lazily if needed. |
| `getwalletinfo` | Adds `receive_address`, `receive_address_index` and `address_rotation_exhausted`; the existing `next_address_index` includes any allocation performed by this call. |
| `getnewaddress` | Existing `{ "index", "address", "label" }` result; always requests a fresh allocation and makes it current. |
| `rhombus address --network <network> --wallet <path>` | Prints the current receive address and persists a fresh selection if needed; returns an explicit error at exhaustion. |
| `rhombus create` | Prints `address_index` and `address` when available. A restore that reserves the entire range still succeeds and reports `address_rotation_exhausted: true`. |

`keygen` has no wallet database or allocation state and still prints the historical
index-zero address. Low-level `WalletKeys::default_address()` also remains index
zero. Those APIs do not advance the persistent receive selection.

A configured mining payout is copied into the node configuration. Starting a
miner with a wallet address does not let the wallet replace that configuration
automatically; it continues paying the supplied address, which remains valid.

## Migration, recovery and exhaustion

A fresh wallet starts with its initial current receive address. Existing wallets
without rotation metadata keep their historical addresses, labels and scan range;
their next current receive selection is allocated beyond the already reserved
range. A phrase/key restore likewise reserves its explicit historical range
before selecting a new current address. The original default-address API remains
available to low-level callers for compatibility; it is not the rotating receive
selection or the new change-allocation policy.

All automatic allocation shares the existing finite range of **4096 indices,
0 through 4095**. Receive addresses, manual addresses, change addresses and unused
reservations all consume that range. If allocation is exhausted, the current
selection may be absent. Receive/status RPC reports null address fields with an
explicit exhaustion flag; manual allocation and change construction that require
another index return an error. The CLI `address` command likewise reports an
error when no current or fresh address is available. An unused current address
can remain available even when no additional index can be allocated, so the RPC
exhaustion flag describes availability of the current selection. The wallet must
not silently reuse index zero or another old address.
Scanning already allocated addresses and existing funds continues; exhaustion
must not cause receipts to disappear or abort otherwise valid scanning. An exact
spend needing no change does not require another change index; it can still retire
the current receive selection.

Before a seed/key restore, preserve the highest reserved index, including change
keys and unpaid reservations left by failed builds. `--restore-through` is an
inclusive historical bound, not a count of visible receipts. Underestimating it
can omit change keys or reuse an index. A stopped wallet-database backup preserves
the allocation/current-address metadata directly. Use a new account or wallet
for future allocation when the current account reaches its bound.

Scanning tries the legacy key plus each allocated separate ML-KEM key. Automatic
rotation therefore increases scan cost as the allocated range grows. It does not
provide unbounded address issuance or hide reuse of already shared addresses.
See [operations](operations.md) for recovery bounds and backup commands.

## Validation

Validation on **2026-11-16**, with Rust **1.100.0**, covered:

```sh
RUSTFLAGS='' cargo test -p wallet --locked --offline -- --test-threads=2
RUSTFLAGS='' cargo test -p runtime --lib --test rpc --test sync --locked --offline -- --test-threads=2
RUSTFLAGS='' cargo test -p runtime --test walletd --locked --offline -- --test-threads=2
cargo fmt --all -- --check
RUSTFLAGS='' cargo check --workspace --all-targets --locked --offline
RUSTFLAGS='' cargo clippy --workspace --all-targets --locked --offline
python3 scripts/check_tor_network.py
git diff --check
```

All checks completed successfully. The tested scope passed **157 unique tests**:
45 wallet tests, 104 runtime unit tests, one control-RPC integration test, six
synchronization integration tests and one live wallet-daemon integration test.
One wallet performance benchmark remained ignored. A separate 19-test wallet-daemon
unit run also passed; those tests are included in the 104 runtime units and are
not counted twice. This was targeted wallet/runtime testing plus workspace-wide
compilation and Clippy, not a new complete workspace test run.

Six wallet regressions cover full/compact receipt parity and reorg/reopen
persistence, distinct change on repeated builds with continued scanning of all
allocated keys, migration/restoration beyond reserved ranges, concurrent current
address readers, exhaustion without partial change reservation or blocked
receipts, and scan failure rollback with corrupt-current metadata rejection.
Runtime tests cover receive/status RPC, manual selection, exhaustion and live
daemon receipt/rebroadcast behavior. Formatting, the network source guard and
whitespace checks passed. Clippy exited successfully with existing legacy
warnings and no new diagnostics from this change.

Local result logs are `/tmp/rhombus-rotation-wallet-tests.log`,
`/tmp/rhombus-rotation-runtime-tests.log`,
`/tmp/rhombus-address-walletd-tests.log`,
`/tmp/rhombus-address-walletd-integration.log`,
`/tmp/rhombus-rotation-workspace-check.log` and
`/tmp/rhombus-rotation-clippy.log`. Prior embedded-network test counts describe
a separate change and must not be added to these results.
