# Separate ML-KEM keys for diversified addresses

Status: implemented draft for wallet/address derivation; no public-network
activation or independent external audit is implied.

## Motivation and rule

The original address contains `d || pk_d || ek`, with the same ML-KEM public key
`ek` at every diversifier under a full viewing key (FVK). Comparing two shared
addresses therefore links them. New addresses derive a separate ML-KEM-768 pair
from secret FVK material and the address diversifier. The existing Pallas key,
spending-key derivation and coin relation remain unchanged.

The new derivation is BLAKE2b-256 under a new, dedicated 16-byte personalization
over `rivk || ak || nk || d`, followed by the existing ML-KEM seed expansion tag
and deterministic FIPS 203 key generation. All fields have fixed lengths.
Temporary seed material is zeroized. The old derivation remains available only
for recognizing and receiving legacy addresses.

## Compatibility and state

There is no change to canonical address or action bytes, transaction IDs,
signature inputs, proofs, fees, minting, nullifiers, block limits, genesis or
consensus validity: senders already encrypt to the opaque ML-KEM key in an
address. Existing senders can pay new addresses. Old receiving software cannot
discover payments to the new keys; wallet downgrades are unsupported.

Wallet metadata records the first index using the new address scheme. A new
wallet starts at zero. An existing wallet with no scheme marker preserves all
previously issued addresses and labels, including its default address, and
starts the new scheme at its next unused index. The migration marker and address
allocation must be durable before an address is returned. Unknown schema
versions or inconsistent metadata must be rejected rather than guessed.

Owned-coin records append one address-scheme byte (`0` legacy, `1` per-address).
Old records ending before that byte are legacy; other values are rejected.
These are private wallet database records, not transaction encodings. The
scanner retains which key succeeded so RPC reconstructs the actual receiving
address even when legacy and new payments share a diversifier after recovery.
JSON backups use format version 2 to identify the added metadata and coin-record
suffix. There is still no JSON import command; preserve a stopped database copy.

Already shared legacy addresses remain linkable. Reissuing an address preserves
its identity; this change does not conceal reuse of the same address. Recognize
both complete legacy and new address encodings when testing wallet ownership.

## Scanning and recovery

Try the legacy receiver key plus every new address key in the configured range.
Legacy scanning recovers old payments at any diversifier. Normal wallets cover
all issued new addresses; a seed/key restore needs an explicit highest address
index covering the previously issued new addresses, including unpaid gaps.
Never infer complete recovery from a finite automatic gap limit. Reserve restored
indices before issuing more addresses. Increasing the historical range requires
rescanning from genesis; do not silently apply it only to future blocks.

Derive scanning keys once for a scan context and try every candidate on every
action, including after a match. Retain commitment checks for compact ciphertexts
and match a per-address candidate's diversifier against the recovered coin.
Preserve the previous balanced decryption work and one nullifier calculation per
output. This is not a constant-time guarantee. No classical routing hint or
public stable key identifier is added. CPU cost grows with addresses times
outputs; enforce an explicit local resource bound, report it, and fail rather
than silently omitting keys.

The wallet limits new issuance to indices 0 through 4095. Normal scans cover
only issued new indices; the legacy key is one additional candidate. Seed/key
recovery requires `--restore-through` specifying the inclusive upper index and
reserves that range against reuse. Migrated legacy wallets beyond this range
remain readable but refuse new issuance; use a fresh account for new receipts.
Recovery with a smaller historical allocation bound can reuse diversifiers
previously used in legacy addresses. Preserve the original database/allocation
metadata or use a fresh account when the old allocation range is unknown.

## Failure cases and validation

Cover deterministic distinct keys, FVK export/import, legacy and new payments,
full/compact agreement, wrong keys, mismatched diversifiers, corrupt ciphertext,
high-index seed restoration, persisted allocation/reopen, migration preserving
old address bytes, and invalid/oversized restoration ranges. Validate that no
candidate loop exits early on ownership and record a local scan-cost measurement.
The exact wallet limits and CLI recovery commands belong in the operations guide.

This closes the shared-ML-KEM-field link between new addresses. It does not make
Pallas commitments, signatures, or proofs post-quantum, nor promise traffic
anonymity. Independent protocol/cryptography review remains required before
public-network activation under CONTRIBUTING.md.

## Local cost measurement

One development-machine run used Rust 1.99.0, test-profile optimization level 1,
32 repeated synthetic compact outputs, cached scan keys, and eight alternating
owned/foreign samples. Other builds and tests ran concurrently, so these are
cost illustrations rather than stable performance or timing-privacy results.

| Separate address keys | Total keys including legacy | Owned scan mean | Foreign scan mean |
|---|---|---|---|
| 1 | 2 | 162 ms | 158 ms |
| 4 | 5 | 342 ms | 311 ms |
| 16 | 17 | 1,063 ms | 1,148 ms |

Key derivation took approximately 0.62, 2.08 and 7.73 ms respectively, outside
the scan timings. The 4,096-key ceiling is a local resource guard, not a promise
that scanning at that limit is practical. Choose the smallest recovery range
known to cover all previously used new addresses, and measure real workloads.

## Verification of this implementation

`cargo check --workspace --all-targets --locked --offline`, workspace rustfmt,
and `git diff --check` passed. Tests were run with two test threads and local
TCP permissions for runtime integration:

```sh
cargo test --workspace --exclude chain --locked --offline --no-fail-fast -- --test-threads=2
cargo test -p chain --test chain --test mempool --locked --offline -- --test-threads=2
```

These runs passed 458 non-chain tests and 29 chain integration tests. The 29
chain unit tests also passed in the workspace run, for 516 passing tests in
total. Three existing measurement/table-generation tests stayed ignored. The
only failing test is the previously documented seed derivation pin
`seed::tests::derivation_is_pinned_and_accounts_differ`; this work does not
change spending-key derivation or its expected vector. See
[the baseline compatibility notes](public-transaction-fees.md).

Coverage includes distinct address keys, legacy decoding, full/compact receipt
scheme agreement, persisted migration/default addresses, metadata corruption,
bounded recovery at index 42 plus legacy index 5000, prevention of recovered
index reuse, and correct RPC receipt addresses. CI YAML and local documentation
links were checked locally. Hosted CI, hosting security settings, and external
independent reviews have not been performed by adding these files. Remaining
dependency advisories are recorded in [the operations guide](operations.md).
