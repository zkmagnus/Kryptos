# Header reads and side-chain admission

Proposal before implementation: read the fixed block-header prefix for header
workflows, and check whether a side branch is eligible for reorganization before
writing its new body to storage.

The existing database stores an encoded block under its header hash. Header-only
reads will decode only that prefix and require its hash to match the requested
key. Missing records remain `None`; truncated or malformed headers and database
errors remain errors. Header reads intentionally do not claim to validate the
transaction body. Full block reads remain the path for body decoding, serving,
and reorganization state validation. Opening a chain still fully decodes its
current tip once, preserving the startup body-corruption check. No schema or wire
encoding changes. Historical body corruption is detected on a full block read,
serving or reorganization, rather than on inventory membership or header lookup.
An intact header does not mean a damaged body will be downloaded again after an
inventory announcement. There is no automatic repair protocol: stop the node,
preserve the damaged database for diagnosis, then restore a trusted stopped copy
or validate history into a fresh chain directory. Preserve the wallet and its
backups separately.

Currently side-block validation writes the body before the caller rejects a
fork below its checkpoint or maximum reorganization depth. Admission will first
walk header ancestry, require consecutive heights, and reject a forbidden fork
before proof verification or any persistent write. It will stop at the oldest
eligible fork height. An eligible side block still requires its original header,
proof, signature, and transaction-shape checks before storage; a stronger branch
still requires full state validation during reorganization. Header ancestry will
be retained as hashes, loading bodies only when the branch wins on work.

These changes do not modify transaction validity, proofs, amounts, fees,
emission, nullifiers, or the reorganization depth configured for a network. They
remove persistent side effects from rejected branch admission and reduce work
on known-block and header requests. Existing compatibility/activation policy for
network parameter changes is documented separately in release-hardening.md.

Regression checks cover missing/corrupt/header-only reads, rejection without a
stored body or work index, ancestry that ages beyond the admissible fork window,
and a successful reorganization at the configured depth boundary.

The walk requires strictly decreasing stored heights and stops at the configured
fork floor; it has no additional arbitrary branch-length cap. An eligible branch
with many lower-work blocks can therefore still require time and a hash vector
proportional to its ancestry. The exact 50/51-depth regression uses synthetic
stored headers to isolate admission policy; separate mined-block integration
regressions exercise actual proofs, work comparison, and reorganization at a
small configured boundary.

Frontier retention must preserve both the reorganization window and transaction
anchor history. Pruning only at `tip - max_reorg_depth` loses otherwise permitted
anchors when the anchor window is larger, and may lose anchors needed immediately
after reverting to an eligible fork. Keep frontiers down through
`tip - (max_reorg_depth + anchor_max_age)`, using saturating arithmetic, after
normal application and completed reorganization. This preserves the documented
anchor acceptance rule across every retained fork, at the cost of retaining more
small tree frontiers. Databases already pruned by older binaries cannot recreate
missing frontiers automatically; a resync may be needed for full old-anchor
coverage. Network rule parameter compatibility remains checked separately by the
existing rules digest.

## Focused validation and local measurement

On November 18, 2026, the storage library tests passed (17 passed, 2 explicit
measurements ignored). The side-branch admission unit tests passed at depths
50/51 and below a checkpoint. Commands used portable Rust CPU flags and two
Cargo build jobs with the pinned Rust 1.100.0 toolchain.

The explicit decoding measurement ran on x86_64 Linux in the optimized test
profile against a warm local redb database. Its synthetic maximum-shape body was
46,579,381 bytes: 512 repeated transactions with 16 actions each and dummy
proof/signature bytes. For 20 reads, full block decoding took 5,509,328 microseconds
in total (275,466 microseconds/read); header-only reads took 167 microseconds in
total (8.35 microseconds/read). Both accessors returned matching headers.

This isolates avoided transaction parsing and allocation. It does not measure
cold-disk I/O, proof verification, valid-block throughput, Tor transfer, or network
capacity. The body is structurally decodable but deliberately not consensus-valid.
Repeat with:

```sh
RUSTFLAGS='' CARGO_BUILD_JOBS=2 cargo test -p storage --lib \
  measure_header_reads_against_full_block_decoding --locked --offline \
  -- --ignored --nocapture
```
