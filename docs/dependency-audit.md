# Dependency audit review — 2026-11-21

This review checks the supplied dependency checklist against the workspace
manifests, checked-in vendor sources, resolved Cargo feature graph, and production
call sites. A dependency that is useful for a possible future feature is not
automatically a missing dependency today. This review does not replace a current
RustSec audit or establish public-release readiness.

## Confirmed hardening changes

- Declare `rand_core/getrandom` directly in the chain, wallet, P2P, and runtime
  manifests. Wallet and chain already requested it directly; P2P and runtime
  now do so too. Generic RNG consumers inherit plain `rand_core = "0.6"` from
  the [workspace manifest](../Cargo.toml). Runtime already has `rand` as a
  production dependency, so the original checklist's claim that production
  lacks an RNG is not correct. These declarations do not rely on `rand`,
  `reddsa`, or Halo2 enabling the feature through feature unification.
- Set release `overflow-checks = true`. This provides a runtime overflow guard;
  protocol arithmetic must still validate inputs and return errors rather than
  relying on an overflow panic.
- Deny `clippy::arithmetic_side_effects` in the chain, protocol, and storage
  libraries. Keep the broader workspace warning for other crates. All ten
  workspace crates already inherit workspace lints through `[lints] workspace =
  true`; this did not require adding missing lint inheritance. CI also runs an
  explicit `-D clippy::arithmetic_side_effects` check over all targets of these
  three packages and the workspace path dependencies Cargo checks with them.
- Compile `halo2_proofs`, `pasta_curves`, and `halo2_gadgets` with test-profile
  `opt-level = 3`, retaining the workspace's default test optimization level 1.
  This changes dependency optimization, not the proof system or consensus.
- Add a `cargo-deny` policy and CI check alongside the existing strict
  `cargo-audit` check. Keep advisory failures visible rather than adding advisory
  exclusions to obtain a passing result. CI uses `cargo-deny` for versions,
  licenses, and sources; `cargo-audit` checks advisories and yanked releases
  against the entire lockfile, including inactive optional dependencies.
  See [dependency maintenance](dependency-maintenance.md)
  for the existing unresolved advisory findings.

## Checklist items already satisfied

| Item | Evidence and conclusion |
| --- | --- |
| Rust version | `rust-toolchain.toml` selects `1.100.0`, matching workspace `rust-version = "1.100"`. Local commands on 2026-11-21 report `rustc 1.100.0 (0ef1bc386 2026-11-09)` and `cargo 1.100.0 (3acc79c0c 2026-11-05)`. The installed toolchain satisfies the declared MSRV; the pin is retained. |
| Tokio runtime features | [Runtime](../crates/runtime/Cargo.toml) explicitly requests `rt-multi-thread`, `macros`, and `signal`; [P2P](../crates/p2p/Cargo.toml) explicitly requests `macros`. Test-only features are declared under dev dependencies. These required features do not depend solely on Arti enabling them. |
| Batch and parallel proof verification | The locked [Halo2 manifest](../vendor/halo2_proofs/Cargo.toml) enables `batch` and `multicore` by default. `multicore` enables Rayon through `maybe-rayon/threads`. [Chain validation](../crates/chain/src/validate.rs) already queues proofs and verifies a `ProofBatch`; the vendored batch verifier uses `into_par_iter()`. A direct Rayon dependency is unnecessary for the existing batch path. |
| Wallet witness tracking | Wallet already depends on `shardtree = "0.6"`. Its [witness tree](../crates/wallet/src/tree.rs) supports retention, witnesses, checkpoints, and rollback. `incrementalmerkletree` is not being used alone as a substitute for witness tracking. |
| Lockfile | `git ls-files --error-unmatch Cargo.lock` succeeds. The root lockfile is already tracked, and normal validation uses `--locked --offline`. |
| Fuzz manifest | The excluded [fuzz project](../fuzz/Cargo.toml) already declares `libfuzzer-sys = "0.4"`. Its target accepts `&[u8]`, so it does not need a direct `arbitrary` dependency for structured inputs. The separate vendoring gap remains open below. |

The locked host dependency tree contains one version each of `pasta_curves
0.5.2`, `halo2_proofs 0.3.5`, `halo2_gadgets 0.5.0`, and `halo2_poseidon 0.1.0`.
`cargo tree -d --locked --offline` does not report these packages as duplicates.
Other duplicate dependency versions exist; a duplicate elsewhere in the Tor graph
does not by itself establish a Pasta/Halo2 trait mismatch.

## Dependencies not added without a corresponding feature

- **`tracing` and `tracing-subscriber`:** runtime already has a [leveled logger](../crates/runtime/src/logging.rs)
  with terminal and file output. A subscriber could improve integration with
  upstream tracing events, but requires an explicit logging change and review of
  sensitive output. Adding dependencies alone would not enable that behavior.
  The existing P2P/runtime test dependency on `tracing = "=0.1.44"` now shares a
  workspace declaration; no new production tracing dependency was introduced.
- **`anyhow`:** runtime exposes a [typed `thiserror` error enum](../crates/runtime/src/error.rs).
  Using `anyhow` in binary entry points is an option, not a build requirement.
- **`argon2`:** wallet files and JSON backups currently store secrets in
  plaintext, as documented in [the library](../crates/wallet/src/lib.rs) and
  [backup implementation](../crates/wallet/src/wallet/backup.rs). Passphrase
  encryption requires an authenticated, versioned format, KDF parameters, and a
  recovery/migration design. Adding Argon2 alone would not encrypt existing
  data. The empty BIP 39 passphrase in [seed derivation](../crates/wallet/src/seed.rs)
  is a separate compatibility rule and must not be changed as dependency cleanup.
- **`criterion`:** add it with actual proving/verifying benchmarks if needed.
  The existing [wallet performance test](../crates/wallet/tests/performance.rs)
  measures compact scanning with standard-library timing; there is no Criterion
  benchmark target requiring a new dependency.
- **`directories`:** [runtime paths](../crates/runtime/src/paths.rs) intentionally
  use `./kryptos-data`, shared with the desktop application. Switching to an
  operating-system user-data path changes where existing users' data is found;
  it requires a separate behavior/migration decision.
- **Encoding and RPC frameworks:** no direct `hex`, `hkdf`, `bincode`, `borsh`,
  `axum`, or `hyper` dependency is needed to satisfy the supplied checklist.
  Consensus encoding, ML-KEM KDF construction, and RPC changes require review of
  their actual call sites rather than adding an unused package.

## ML-KEM deterministic feature

The production wrapper uses `MlKem768::generate_deterministic` to reproduce the
receiver key pair from seed material. Its public encapsulation method requires
`CryptoRng + RngCore` and calls randomized `encapsulate`. See
[crypto encryption](../crates/crypto/src/encryption.rs) and the
[protocol sender](../crates/protocol/src/encryption.rs).

Searching workspace crate sources found no direct `encapsulate_deterministic`
call. Keep deterministic key generation available for recovery, and preserve
fresh, securely generated encapsulation randomness. The dependency's feature
name alone is not evidence of unsafe production encapsulation.

## Remaining supply-chain work

The latest online audit recorded in [dependency maintenance](dependency-maintenance.md#fresh-online-audit-on-2026-11-21)
on 2026-11-21 failed: three vulnerabilities and four denied unmaintained warnings
in the 589-package lockfile. Those findings remain release blockers. Adding
`cargo-deny`, declaring RNG features, and enabling overflow checks do not repair
those upstream packages. This review neither updates the dependency versions nor
adds advisory exclusions, and does not claim a new successful security audit.

The excluded fuzz project cannot resolve fully from the current vendor tree:
`libfuzzer-sys` is not vendored. Preparing offline fuzzing requires a separate
reviewed dependency/vendor update. Preserve the local RandomX and bindgen patches
when maintaining vendor sources; do not replace the tree wholesale.

## Reproducing the dependency inspection

```sh
rustc --version
cargo --version
git ls-files --error-unmatch Cargo.lock
cargo metadata --locked --offline --format-version 1 > /dev/null
cargo tree -d --locked --offline
cargo tree --locked --offline -p runtime -e features -i tokio
cargo tree --locked --offline -p p2p -e features -i rand_core@0.6.4
cargo deny --locked --offline check bans licenses sources
rg 'encapsulate_deterministic' crates
```

The final `rg` command returns status 1 when no match is found; that is the
expected result for this review. Cargo's offline dependency inspection uses the
checked-in vendor sources and does not refresh security advisories. Report build,
Clippy, tests, and security-policy validation separately from these source
inspection results.

## Validation on 2026-11-21

- `cargo metadata --locked --offline --format-version 1` passed. The 589-package
  resolution and resolved feature graph are unchanged by these edits; the
  explicit RNG feature was already enabled in the combined workspace build.
  `Cargo.lock` has no diff.
- `cargo fmt --all -- --check`, `git diff --check`,
  `cargo check --workspace --all-targets --locked --offline`, and
  `cargo clippy --workspace --all-targets --locked --offline` passed. Existing
  Clippy warnings outside the new production arithmetic errors remain.
- `python3 scripts/check_tor_network.py` and
  `python3 scripts/check_seed_vectors.py` passed.
- `cargo test -p chain -p protocol -p storage --locked --offline --
  --test-threads=2` passed: 240 tests, zero failures, and three ignored measurement
  tests. This includes protocol address/body/header/transaction tests, storage
  nullifier tests, and chain snapshot/integration tests. It is not a full
  workspace runtime-test or cross-platform release-build claim.
- With the pinned, checksum-verified `cargo-deny 0.19.9`,
  `cargo deny --locked --offline check bans licenses sources` passed. It reports
  existing duplicate versions outside the Pasta/Halo2 deny list as warnings.
  No advisory exclusion was added.
- A fresh online `cargo audit --deny warnings --db <audit-db>` run refreshed
  RustSec and the crates.io index and checked all 589 locked packages, including
  yanked-release checking. The database contained 1,555 advisories at commit
  `f291af9b1cc0d21dfcea1709d6b037963cef262b`, dated 2026-11-20. It exited 1 with
  three vulnerabilities (`crypto-bigint`, `libsqlite3-sys`, `rsa`) and four
  denied unmaintained warnings (`bincode`, `chrono`, `humantime`, `paste`). No
  yanked-release findings or fetch errors were reported. CI retains the online
  `cargo audit --deny warnings` command. A passing versions/licenses/sources
  check is not a passing security audit.

## Direct RNG and untrusted-arithmetic follow-up

The inverse feature tree uses `rand_core@0.6.4` because another dependency
generation also uses `rand_core 0.10.1`. After moving the entropy requirement to
consumer manifests, the direct workspace edges under `rand_core/getrandom` are
exactly chain, P2P, runtime, and wallet. Manifest inspection checks the actual
`[lints].workspace` TOML value in all ten crates; finding an unrelated
`version.workspace = true` line would not establish lint inheritance.

`RawCoin::MAX` is `u64::MAX`, not `i64::MAX`. Decoding preserves that full range,
and conversion to an `i64` is fallible. This follow-up does not narrow the
accepted amount range. `ValueSum`'s former claim that fewer than `2^64` maximum
amounts cannot overflow `i128` was incorrect; its documentation now states the
safe `2^63` contribution bound and the precondition on composing sums. The
current builder limits each side to 16 actions, so each side totals less than
`2^68`, and their difference fits `i128`. Its per-action signed conversions can
still reject individual amounts above `i64::MAX`; this existing builder behavior
is separate from the decoder's accepted range.

The reviewed fee and mint paths use checked conversion, multiplication, fee
accumulation, and subsidy addition. Coinbase balance conversion is fallible.
New boundary regressions cover `i64::MAX`, the next unsigned value,
`u64::MAX`, a maximum-size action sum, decoded extreme transaction fees, and
coinbase balances outside the signed range. Invalid values must produce `Err`
before authorization rather than relying on a release overflow panic.

The explicit follow-up Clippy command first exposed three additional dependency
operations: modular scalar subtraction in crypto, modular field negation in the
circuit's public inputs, and an unchecked proof-envelope capacity addition. The
two modular operations have single-binding documented exceptions; the capacity
uses `checked_add` and returns the existing `InvalidProof` error on overflow.
The full command then passed with zero arithmetic diagnostics:

```sh
cargo clippy -p chain -p protocol -p storage --all-targets --locked --offline -- -D clippy::arithmetic_side_effects
```

Follow-up validation passed: all-target checks for P2P and runtime; 129 protocol
unit tests (including the four new boundary regressions); nine crypto signature
tests; and five circuit proof tests. Formatting and whitespace checks also
passed. These targeted reruns do not replace the separately recorded 240-test
chain/protocol/storage run. The resolved package/feature graph and `Cargo.lock`
remain unchanged.
