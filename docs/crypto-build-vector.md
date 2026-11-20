# Crypto build vector after the generator-domain migration

This is a test-fixture correction. No production crypto, key derivation,
transaction encoding, circuit, verifier, genesis or consensus parameter is
changed by this correction.

Commit `7a97c456` changed `crates/crypto/src/curve.rs` from `null:Generator` and
`null:DiversifiedBase` to `kryptos:Generator` and `kryptos:DiversifiedBase`.
The generator tables and proof vectors were already updated as described in
[circuit.md](circuit.md) and [implementation-notes.md](implementation-notes.md).
The aggregate digest expected by `crypto/tests/build_consistency.rs` still
referred to the old domains. The full workspace run therefore failed that test
before this fixture correction.

The test uses public synthetic keys, computes diversified bases, commitments,
nullifiers and a deterministic signature, and hashes their canonical encodings.
Changing the curve domains changes several of those inputs, even though the
spending-key derivation itself is unchanged.

To establish the cause, a temporary isolated source copy of the crypto crate was
created with the same vendored dependencies and Rust 1.100.0. Only the two domain
strings were reverted. Its unchanged build-consistency test passed and printed
`94d44403f3a413bc064f83761424cbbb69fe889c6833f1bcbf7d05d0acf944d2`, exactly the
former fixture. With the current domains, the expected vector is
`e1081cf184e5f362183188e288ffcf789ac426b22059076f062b58d3f4f37eaf`.
The comparison does not claim an independent cryptographic audit: it isolates
which existing source change explains the inconsistent fixture.

The correction updates only that digest and its explanatory comment. Tests
continue to reject malformed commitments, verify the signature and reject a
wrong message; the comparison still detects subsequent unreviewed output changes.
The reference seed compatibility script independently checks the spending-key
hierarchy and remains unchanged.

Commands for portable/native comparison in the optimized test profile:

```sh
RUSTFLAGS='' CARGO_BUILD_JOBS=2 cargo test -p crypto --test build_consistency --locked --offline -- --nocapture
RUSTFLAGS='-C target-cpu=native' CARGO_BUILD_JOBS=2 cargo test -p crypto --test build_consistency --locked --offline -- --nocapture
```

The explicit timing measurement in the same test target remains ignored by these
commands. This local comparison is separate from the CI release-profile matrix
and does not claim cross-platform execution.

On November 18, 2026, both commands passed (one vector test passed and one timing
measurement ignored per command), with the identical current-domain digest
above. The isolated old-domain comparison also passed its unchanged former
expected digest. No production source was modified for either comparison in
the working checkout.
