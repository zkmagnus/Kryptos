# Validated work and fork choice

Rhombus represents cumulative proof of work as `chain::target::ChainWork(U256)`.
All consensus arithmetic uses integers. For a validated nonzero target `t`, a
block contributes `floor(2^256 / (t + 1))`, evaluated as
`(!t / (t + 1)) + 1`. The maximum target contributes exactly one; it is handled
explicitly because its denominator would require 257 bits. Zero is rejected as
`InvalidTarget`, because its mathematical work is `2^256`, outside the type.
Compact target decoding already rejects zero.

Genesis contributes **zero work**. It is the fixed, unmined network anchor.
Every other block adds its work to its parent's indexed cumulative work with
`checked_add`. Overflow is `ChainWorkOverflow`; it never wraps or saturates, and
the child is not stored or applied.

Header validation checks the exact compact `nBits` against the difficulty
adjustment result for that parent's ancestry. An alternative encoding of the
same numeric target is rejected. Work is calculated from the validated target
returned by this check. Headers accepted for sync must also pass linkage and
proof-of-work validation, or prove their hash ancestry to a trusted checkpoint.
A mere height below a checkpoint is not sufficient proof of ancestry.

Fork choice compares the indexed totals. A strictly larger total wins. Equal
work keeps the first successfully imported tip; a smaller block hash cannot
replace it. "First seen" here means accepted block arrival, not an unverified
header announcement or an inventory advertisement. Side branches retain their
work index so importing another descendant does not rescan and sum both chains.

The `chainwork` redb table maps a block hash to 32 big-endian bytes. `Store::apply`
and `Store::put_block` write the bytes and work in the same database transaction.
Reverting a block retains both its bytes and work. Recovery of an interrupted
reorganization reuses the recorded values. Genesis and the current tip must have
work index entries when the chain opens.

Storage layout version **2** requires this index. An older database is refused
with the existing resync error; no unvalidated values are reconstructed from
claimed targets. Consensus revision **2** records exact compact difficulty and
checked 256-bit accumulation in the rules digest. The configured mainnet block
interval is **300 seconds**; changing these launch parameters is not a scheduled
upgrade of an existing live chain.

`MIN_CHAIN_WORK` is node download/IBD policy, initially zero. It is not part of
block validation or the consensus rules digest. Sync only downloads bodies once
validated peer header work reaches `max(local_tip_work, MIN_CHAIN_WORK)`. Raising
this threshold for a release should accompany an appropriate checkpoint.
Header candidates awaiting the work threshold or a checkpoint are spooled to an
anonymous temporary file in the datadir, with only the difficulty lookback in
memory. Candidates below a future checkpoint stay unauthenticated until the
hash chain reaches that exact configured checkpoint, including across response
batches. They cannot trigger body downloads before that point. Exact DAA checks
still apply when checkpoint ancestry permits skipping RandomX.

Implementation choices:

- `crates/chain/src/target.rs`: one work type and explicit boundary arithmetic;
  removes the redundant 512-bit accumulator.
- `crates/chain/src/validate.rs`: returns the DAA-validated target, checks work
  overflow before transaction verification, and passes the computed index value
  to storage. Exposes header rules for headers-first synchronization.
- `crates/chain/src/chain.rs`: reads indexed cumulative work for fork choice and
  crash recovery; defines genesis work and preserves arrival-order ties.
- `crates/chain/src/error.rs`: gives overflow a distinct error.
- `crates/chain/src/params.rs`: sets the requested five-minute mainnet interval
  and documents the resulting 100-block difficulty window (8 hours 20 minutes).
- `crates/storage/src/store.rs`: stores cumulative work atomically beside each
  block and refuses the old layout rather than silently serving an absent index.
- `crates/chain/tests/chain.rs`: covers monotonic persisted work, arrival-order
  ties even when the later hash is smaller, overflow without a tip mutation,
  and equivalent noncanonical `nBits` rejection.
- `crates/runtime/tests/sync_adversarial.rs`: uses the one-RTT version exchange
  and verifies invalid `nBits` cannot trigger a body request.
