# CI dependency feature cleanup

This change removes unused dependency features that retained four RustSec
warnings in `Cargo.lock`. It does not change transaction encodings, consensus,
cryptographic algorithms, RandomX parameters, or the vendored RandomX C++ source.
No advisory is ignored and the CI audit still denies warnings.

## Embedded Arti dependencies

The workspace pins Arti client, service and supporting Tor crates to `=0.48.0`
and Rust to 1.100.0. Selected Arti features are `tokio`, `native-tls`, `compression`,
`onion-service-client`, `onion-service-service` and `vanguards`. Full vanguard mode
is also selected at runtime. No daemon/SOCKS, bridge/PT or experimental PoW feature
is enabled. The former `tokio-socks` dependency and strict-authentication patch
have been removed from the active dependency graph, and the unused
`vendor/tokio-socks` directory has been deleted.

The Arti packages, `futures-util`, `fs-mistrust` and `safelog` use permissive
`MIT OR Apache-2.0` licenses. The resolved workspace graph contains 589 packages including ten workspace crates.
It also includes `option-ext` under
MPL-2.0 and other documented upstream license expressions. `r-efi` offers
`MIT OR Apache-2.0 OR LGPL-2.1-or-later`; this alternative license expression must
not be reported as mandatory LGPL linkage. The graph does not include `equix`
or `hashx` because `hs-pow-full` is disabled. Enabling that experimental feature
would require reviewing its additional LGPL dependencies and distribution terms.

Arti's native TLS backend uses OpenSSL development headers/pkg-config on Linux
and platform TLS on macOS/Windows. CI installs Linux native prerequisites. Keep
runtime shared libraries available when packaging binaries. New registry sources
are vendored alongside existing packages without overwriting locally patched
RandomX or bindgen sources. A dependency update must refresh `Cargo.lock`, vendor
sources/checksums and the package-license review together. Do not run a vendor
replacement that discards existing local patches.

The migration's isolated API probe compiled successfully and workspace metadata
resolved offline with an empty Cargo home, entirely from this repository. Final
verification on 2026-11-16 with Rust 1.100.0 passed 545 workspace tests, with zero
failures and nine ignored tests (two public-Tor exercises, six measurements and one fixed-base
table generation test).
Formatting, the source network guard, whitespace checks and Clippy passed; legacy
Clippy warnings remain outside the new networking code. No fresh RustSec audit of
this expanded graph was run. Dependency security updates for embedded Tor require
a new application release.

## Dependency validation on 2026-11-18

The cached audit command failed with three vulnerabilities and two unmaintained
dependency warnings:

```sh
cargo audit --deny warnings --no-fetch --db "$HOME/.cargo/advisory-db"
```

The advisory database was commit `02e2517f457a359fc6d3440ea4560c8ea188fee8`,
dated 2026-11-15. Offline dependency-tree checks, including workspace
`--all-features --target all`, established the following scope:

| Package | Advisory | Scope and required update |
| --- | --- | --- |
| `crypto-bigint 0.5.5` | `RUSTSEC-2026-0387` | Timing variability; retained in the lockfile through inactive SSH elliptic-curve dependencies, absent from the selected build graph. Patched in >=0.7.6. |
| `libsqlite3-sys 0.38.2` | `RUSTSEC-2026-0459` | Active through `tor-dirmgr` and `rusqlite`; patched crate >=0.39.0. Selected features link system SQLite, without `bundled`; review the system library separately. |
| `rsa 0.9.10` | `RUSTSEC-2023-0071` | Active through Arti crypto/key-management dependencies; private-key timing advisory, patched in >=0.10.0. Application RSA private-key exposure was not established by this dependency review. |
| `bincode 2.0.1` | `RUSTSEC-2025-0141` | Unmaintained; inactive optional lockfile dependency through `typed-index-collections`. No patched version listed. |
| `paste 1.0.15` | `RUSTSEC-2024-0436` | Unmaintained proc macro active through Arti and supporting crates. No patched version listed. |

The SQLite advisory concerns opening a database and sibling WAL written by a
less trusted party. This host reports system SQLite 3.46.1, older than the
advisory's fixed 3.54.0; distribution backports were not verified. The affected
bundled source is also present in vendor, although not selected by this build.
Fixed crate versions are unavailable in the current vendor tree. Updating them
requires reviewing upstream migrations: current Arti dependencies constrain RSA
to 0.9 and rusqlite below 0.41. The inactive elliptic-curve dependencies and
unmaintained packages also require dependency maintenance.

These findings block the configured `cargo audit --deny warnings` CI check and
public-release readiness. No dependency updates or advisory suppressions were
performed. Restricted network access blocked a fresh database fetch, and the
automatic approval reviewer returned an account/API error for the escalation.
The cached run also could not lock the crates.io index, so it provides neither
current advisory coverage nor yanked-release coverage. A fresh online audit is
still required after remediation.

## RandomX binding generation

Keep bindgen 0.58.1 and enable only its `runtime` feature. The build script uses
the Rust builder API and dynamic libclang, not bindgen's command-line parser,
logging frontend, or PATH search for rustfmt. Disabling those default features
removes clap 2, env_logger, ansi_term and atty from the lockfile. This closes
`RUSTSEC-2021-0139`, `RUSTSEC-2024-0375` and `RUSTSEC-2021-0145` for this dependency
graph without changing the generator version or native ABI.

## RedDSA feature selection

Keep reddsa 0.5.2 and select `alloc` and `zeroize` explicitly instead of its
default `std` feature. `alloc` keeps the existing batch verification and
multiscalar multiplication paths. `zeroize` remains enabled. Rhombus uses its
own canonical signature/key bytes and maps RedDSA errors into its own error
type; it does not need RedDSA's serde derives or `std::error::Error` implementation.

In reddsa 0.5.2, `std` enables `serde`, whose weak optional FROST feature edge
retains frost-core, postcard, heapless 0.7 and atomic-polyfill in the lockfile.
Those FROST dependencies were not in Rhombus's active target build graph.
Removing unused serde/std integration removes that dormant path and
`RUSTSEC-2023-0089`. No signing or verification source is patched, and no package
version is upgraded. The account/key derivation and network activation rules
remain unchanged.

## Verification

Check generated RandomX binding declarations against the previous output,
build the native dependency, and verify a published RandomX hash vector. Run
the crypto tests to cover signatures, malformed inputs, batching and basepoints,
then run the workspace checks with the committed lockfile. Run `cargo audit
--deny warnings` against a freshly fetched advisory database, including yanked
release checks. A no-fetch cached check is useful during development but does
not replace that final online audit.

The feature-only update passed `cargo check -p crypto -p chain --all-targets
--offline` on Rust 1.90.0. Generated RandomX FFI declarations match the previous
output; differences are formatting/trailing commas and a stale generated doc
comment, not types or function signatures. The regression test
`pow::tests::native_bindings_match_the_published_randomx_vectors` uses upstream
`test_a` and `test_b` from `vendor/randomx-bindings-sys/randomx/src/tests/tests.cpp`.

A fresh `cargo audit --deny warnings` fetched 1,509 RustSec advisories and
checked 214 locked packages successfully, including yanked-release checking.
The advisory result is a point-in-time check; CI refreshes it on every audit
run. The local bindgen 0.58.1 future-incompatibility fix and its vendor checksum must
be preserved. A future generator update should recheck the ABI and RandomX
vectors. Historical audit results above predate the embedded Arti graph; refresh
RustSec rather than treating them as current coverage.

## Unused vendor source cleanup

The [vendor usage audit](vendor-usage-audit.md) identified 15 unused source
directories by exact package identity, including obsolete versions. The authorized
cleanup removed those directories (38.49 MiB of logical file bytes), retaining
579 active vendor packages, platform-specific dependencies and local patches.
Locked offline all-features resolution still contains 589 packages, including the
ten workspace crates, with an unchanged dependency graph. The excluded fuzz
workspace still requires a separate `libfuzzer-sys` vendoring step.
