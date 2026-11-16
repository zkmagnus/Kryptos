# Cryptography Audit Fixes

These changes address three findings from the cryptography audit:

- On Unix, wallet databases are created and opened through an owner-only file
  handle (`0600`) with `O_NOFOLLOW`. Permissions on existing wallets are fixed
  before secrets are read, and opening a missing wallet does not create it. The
  database still stores the spending key in plaintext; its protection depends
  on filesystem permissions. Encryption at rest is outside the scope of these
  changes. Non-Unix platforms continue to rely on inherited file and directory
  ACLs.
- Full and compact trial decryption always reconstruct the recipient and
  commitment and derive one nullifier, including when ciphertext authentication
  or parsing fails. `black_box` keeps the discarded computation from being
  optimized away. A local benchmark with 128 notes reduced the owned/foreign
  timing ratio from about 1.422 to about 1.001. This balances cryptographic
  work; it is not a constant-time guarantee. Allocations, wallet writes, and
  payment results can still differ.
- The wallet downloads a batch of public blocks to a temporary file before
  scanning, closes the RPC session before private work begins, and opens a new
  connection for operations after the scan. The daemon schedules polls on a
  fixed time grid and yields to the executor between blocks. This reduces
  timing signals between requests and prevents idle sessions from expiring,
  but it does not hide total scan duration or delays that miss a polling slot.
  Payment and reconciliation operations after the scan can still reveal
  aggregate duration. RAM use is bounded per block; temporary disk use is
  proportional to the entire batch of blocks awaiting a scan and is released
  when synchronization succeeds or fails. The batch is not an atomic chain
  snapshot.
- `scalar_to_base` now returns an error when a scalar does not fit in the base
  field, rather than silently converting a valid value to zero.

Regression tests cover wallet permissions and symlinks, full and compact trial
decryption, reconstruction on malformed ciphertext, field bounds, downloading
before scanning, closing the session before scanning, reorgs, and fixed polling
schedules. The daemon integration test also verifies that a transaction can be
sent after synchronization.

Validation: 101 crypto unit tests, 30 circuit tests, 105 protocol tests,
27 wallet tests, 90 runtime tests, and one wallet-daemon integration test passed
(354 unique tests). One wallet test,
`seed::tests::derivation_is_pinned_and_accounts_differ`, still fails. The same
failure was confirmed on a clean checkout of commit `851546b` and is documented
in `docs/public-transaction-fees.md`. This fix does not change derivation or its
pinned value. The full workspace build and formatting checks for changed files
passed.

There are no consensus-rule or transaction-format changes. The Rust API for
`scalar_to_base` now returns `Result`, and `sync_wallet` closes the download
session, so callers need a new connection for subsequent RPC calls. All
internal callers that need further RPC access have been updated.
