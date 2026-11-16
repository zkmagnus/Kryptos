# Build and Performance Report

This report records local baselines and one measured optimization, not a full
throughput ranking. Consensus, encodings, schemas, and validation rules are unchanged.

## Build Configuration

`rust-toolchain.toml` and the workspace now pin Rust 1.100.0/1.100. This
upgrade supports the embedded Arti migration. The measurements below were
collected with Rust 1.90.0; they have not been repeated with the new compiler.
`Cargo.lock` fixes
versions, and Cargo selects checked-in vendor sources with network access
disabled. Offline builds still require installed Rust and native toolchains.

Local Cargo builds, including development builds, use `-C target-cpu=native`
for the host instruction set. The binary is intended for that machine. CI,
portable releases, and cross-builds override it with `RUSTFLAGS=""` for the
target's default CPU baseline. `RUSTFLAGS` replaces configuration flags;
`CARGO_ENCODED_RUSTFLAGS`, if set, takes precedence over both.
CI runs explicit native-vector comparisons in a separate target directory;
portable release artifacts retain generic flags.

For a portable build in a POSIX shell, use
`RUSTFLAGS="" cargo build --release --locked --offline -p runtime --bins`.
Cross-builds also need a suitable cross-linker and C/C++ cross toolchain. Rust
flags do not independently configure RandomX's CMake compiler flags; that build
must remain appropriate for the target too.

For portable Windows x86_64 builds, use
`$env:RUSTFLAGS = "-C target-cpu=x86-64"`; PowerShell before 7.5 removes empty
environment variables, restoring the native configuration. Unset
`CARGO_ENCODED_RUSTFLAGS` first. See [the operations guide](operations.md) for
platform prerequisites and shell details.

The existing release profile is retained:

| Setting | Current value | Trade-off and decision |
| --- | --- | --- |
| `opt-level` | `3` | Aggressive optimization can increase compile time and code size; retain the existing setting while measuring actual workloads. |
| `lto` | `"fat"` | Enables optimization across crate boundaries, with longer linking and potentially higher peak memory. No measured evidence yet justifies changing the existing value. |
| `codegen-units` | `1` | Allows optimization across a larger compilation unit, at the cost of less parallel code generation. Retain pending a controlled comparison. |
| `panic` | Cargo default, unwind | Preserves current panic behavior; abort is not adopted without checking cleanup and error behavior as well as measurements. |
| `strip` | Cargo default, none | Preserves symbols for diagnosis. Stripping is not treated as a measured runtime optimization. |

No unmeasured allocator, PGO, linker, dependency, SIMD, or unsafe change was added.

## Dependency Audit

Audit source: locked vendor manifests/source and Cargo's resolved feature graph.

| Dependency | Relevant features or CPU selection | Current status | Recommendation |
| --- | --- | --- | --- |
| `halo2_proofs 0.3.5` | Default `batch` and `multicore`; `multicore` enables `maybe-rayon/threads` and Rayon | Both features are already enabled. The existing backend parallelizes parameter generation, FFTs, and other proof work. | Benchmark existing thread counts and contention before introducing another pool or adding parallelism around it. |
| `halo2_gadgets 0.5.0` | Circuit gadgets; test support is enabled through a dev dependency | Uses the existing Halo2 backend. | Measure synthesis and proving separately; do not enable test-only features in production for speed. |
| `pasta_curves 0.5.2`, `ff 0.13.1`, `group 0.13.0` | Pasta defaults include `bits` and `sqrt-table`; optional `glv` is available | Default tables are enabled. No explicit ADX/BMI2/AVX2/NEON runtime dispatcher was found in the locked Pasta source. | Keep portable arithmetic and current tables; test an optional backend only with measured benefit and identical vectors. Native LLVM code generation is separate from an explicit CPU dispatcher. |
| `halo2_poseidon 0.1.0` | Pure Rust field-based Poseidon implementation | No separate SIMD, assembly, or Rayon performance feature in this manifest. | Profile permutations and field arithmetic before changing the implementation. |
| `blake2b_simd 1.0.5` | Runtime x86 detection selects AVX2 or SSE4.1, with a portable fallback | Default `std` support is enabled; CPU selection is already adaptive. | Keep dispatch; do not force an ISA in portable artifacts. |
| `ml-kem 0.2.3`, `sha3 0.10.9` | ML-KEM `std`, `deterministic`, and `zeroize`; SHA3 has an optional assembly feature | ML-KEM uses the locked portable arithmetic/SHA3 path; no optional assembly flag was added. | Benchmark actual full and compact trial decryption before considering another backend. Preserve secret handling and output bytes. |
| `chacha20 0.9.1`, `chacha20poly1305 0.10.1`, `poly1305 0.8.0`, `aes 0.8.4` | ChaCha20 has x86 AVX2/SSE2 detection; AES has supported-target hardware detection and a software fallback; ChaCha's AArch64 NEON path is a separate forced configuration | Existing selection logic is used. No forced AVX2, AES, or NEON configuration was added. | Benchmark the current path; do not assume that a forced backend improves an entire wallet scan. |
| `redb 4.4.0` | `std`; optional metrics and experimental APIs | Requires Rust 1.90. No CPU SIMD or general parallel execution feature is exposed. | Measure transaction count, cache behavior, serialization, and write batching rather than adding CPU flags. |
| `randomx-bindings 0.1.4`, local `randomx-bindings-sys 0.1.5` | Vendored C++ uses x86 AES/SSSE3/AVX2 checks, ARM AES capability checks, and architecture-specific JIT assembly | Built by CMake and bindgen. Rust's `target-cpu` does not set CMake's `ARCH` option. | Keep runtime selection and published hash vectors. Verify native and portable build modes on each platform. |
| `ring 0.17.14` and `curve25519-dalek 4.1.3`, through Snow | Architecture-specific implementations; Dalek includes x86 vector-backend selection | Existing dependency backends are used for transport cryptography. Ring builds C/assembly. | Keep audited backend selection; include native build requirements and transport tests in the platform matrix. |

RandomX needs CMake, C/C++, and libclang; Ring also builds native code. macOS
needs Xcode CLT, CMake, and libclang; Windows MSVC needs Visual Studio C++ Build
Tools, CMake, and LLVM/libclang. RandomX's script handles MSVC runtime linkage
and multi-configuration output directories. The configured CI matrix still
needs actual Linux aarch64, macOS Intel/Apple Silicon, and Windows MSVC results;
this Linux x86_64 session does not establish support on those platforms.

## Local Measurement Conditions

Host: Linux x86_64, Intel Core i7-8550U, four cores/eight threads, Rust 1.90.0,
LLVM 20. No sampling/instruction/heap profiler was installed. Attribution uses
call-level wall time and source inspection, not perf or flamegraphs. No new
tool or dependency was added. Results are specific to this host.

### Clean Release Build

| Build | Wall time | User CPU | System CPU |
| --- | --- | --- | --- |
| Original portable release | 180.190 s | 585.706 s | 21.945 s |
| Native release | 177.138 s | 583.508 s | 21.637 s |

Some testing overlapped the native build. These are recorded observations, not
a controlled comparison or evidence that `native` reduces build time.

For each clean trial, choose target directories that do not exist. Bash's
`time` records wall/user/system time without `/usr/bin/time`:

```sh
unset CARGO_ENCODED_RUSTFLAGS
time RUSTFLAGS="" CARGO_TARGET_DIR=target/perf-clean-generic \
  cargo build --release --locked --offline -p runtime --bins
time RUSTFLAGS="-C target-cpu=native" CARGO_TARGET_DIR=target/perf-clean-native \
  cargo build --release --locked --offline -p runtime --bins
```

Use isolated trials and record compiler/linker versions and available memory.
A repeat in the same directory measures caching, not a clean build.

### Exploratory Proof Timings

One ignored proof-class run per mode provides exploratory timings, not a
causal native-versus-portable speedup claim:

| Actions | Portable prove | Native prove | Portable verify | Native verify |
| --- | --- | --- | --- | --- |
| 2 | 2.380210019 s | 2.188867458 s | 22.363185 ms | 19.895165 ms |
| 4 | 4.313552464 s | 4.007752580 s | 29.111731 ms | 23.552461 ms |
| 8 | 8.918746398 s | 8.116352066 s | 50.173845 ms | 45.591327 ms |
| 16 | 17.337327389 s | 15.868282733 s | 76.658354 ms | 71.203857 ms |

### Compact Scanner and Poseidon Baselines

The native-release compact scanner benchmark times
`scan_compact_block_with_keys`, the production scanner, with two outputs per
block. Key derivation, encryption, and fixture construction are outside timing.
Each entry is the median of three samples; the candidate count includes one
additional legacy key beyond the listed per-address keys.

| Address keys | Two owned outputs, microseconds | Two foreign outputs, microseconds | One owned/one foreign, microseconds |
| --- | --- | --- | --- |
| 1 | 2,833 | 2,808 | 2,425 |
| 16 | 13,978 | 14,525 | 14,893 |
| 256 | 220,059 | 220,326 | 219,800 |
| 4096 | 3,496,735 | 3,492,346 | 3,518,202 |

Scan cost grows with address range. These single-host medians are not timing
privacy guarantees or native-versus-portable comparisons. Full/compact scan
correctness is tested, but only compact scanning was timed, without database I/O.

The native-release Poseidon harness used seven samples of 1,024 operations with
fixed public inputs. Results were checked for consistency outside each timer:

| Operation | Median batch time | Nanoseconds per operation |
| --- | --- | --- |
| `poseidon::merkle_node` | 26.910301 ms | 26,279.6 |
| `poseidon::nullifier` | 55.860376 ms | 54,551.1 |

These are baseline costs, with no before/after optimization claim.

### Storage and Tiny-Block Baselines

Temporary redb databases were under `/tmp`, a tmpfs on this host. These are
memory-backed filesystem measurements, not persistent SSD or durable-media
benchmarks. Native `nullifier_lookup_cost` inserted 1,000,000 rows and committed
the write in 1.059551884 s; 100,000 successful lookups took 143.333651 ms through
the existing API, which opens an individual read transaction per lookup.

Native `coinbase_only_block_import_timing` measured seven imports, excluding
proof creation, mining, and wallet scans. Each block had one coinbase and two
actions. Samples were `[69.456729, 114.381791, 125.101264, 107.161886,
122.052118, 127.295238, 122.722486]` ms; median 122.052118 ms. This fixture does
not establish block capacity, transfer TPS, or dense-block validation cost.

## Selected Bottleneck and Change

`circuit::proof::ProvingKey::verifying_key` regenerated parameters already held
by the proving key. `params()` invokes `Params::new(K)`: generate `n = 2^K`
curve points, normalize them, and run a curve FFT. The patch clones them:

```diff
 VerifyingKey {
-    params: params(),
+    params: self.params.clone(),
     vk: self.pk.get_vk().clone(),
 }
```

Both hold `O(2^K)` parameter arrays. Regeneration includes `O(n log n)` FFT
work; cloning copies the arrays in `O(n)`. Parameters and keys are identical,
with no new shared mutable state or serialization.

Seven portable-release samples measured extraction from an already-built
proving key. Each sample checked that the pinned key description matched:

| Operation | Before, median | After, median |
| --- | --- | --- |
| Extract matching verifying key | 1.700073707 s | 196.868 microseconds |

This measures extraction only, excluding initial proving-key construction. It
does not claim the same speedup in proving, verification, or transaction throughput.

No other hot-path patch was retained. An isolated wallet binary-search
microbenchmark was excluded because it did not measure actual scanning; the
candidate change was removed.

## Consistency Evidence

Release test suites for `crypto`, `circuit`, `protocol`, `wallet`, and `storage`
completed with 299 unique passing tests in each of the portable and native
builds. The same package selection was used in both modes to keep feature
unification comparable. Fixed-input results matched, including full/compact
scan correctness and valid/invalid proof checks. The observed fixed-seed proof
digest matched the before-change, portable, and native runs:

`aa15d30d93a017d94087cde3fc47482915b847906bedbb25bd987a4aba033e17`

The recorded cryptographic-vector digest also matched across the compared
portable/native runs:

`94d44403f3a413bc064f83761424cbbb69fe889c6833f1bcbf7d05d0acf944d2`

The complete transaction encoding from the fixed-seed payment fixture also
matched across generic and native release runs:

`a858d3e77c7b7208c25a103c4571a8c61cfe9f9fe969637ec17ec0d4daf03435`

An additional explicit `RUSTFLAGS="-C target-cpu=x86-64-v2"` run passed all
245 crypto/circuit/protocol tests with the same pinned digests. The portable
and native 299-test runs additionally included storage and wallet tests.

Proof tests reject reordered/modified public inputs and tampered proofs. Each
key extraction checks its pinned description. Fixed-input checks do not prove
equivalence for all inputs, optimization levels, thread counts, or platforms,
and do not substitute for the unexecuted platform CI matrix.

## Reproducing Measurements and Remaining Work

Run from the repository root with `CARGO_ENCODED_RUSTFLAGS` unset. The following
commands reproduce the ignored harnesses. For a portable run, prefix a command
with `RUSTFLAGS=""`; the extraction comparison used that mode.

```sh
cargo test --release --locked --offline -p circuit --test prove \
  proof_size_per_action_class -- --ignored --nocapture --test-threads=1
cargo test --release --locked --offline -p circuit --test prove \
  verifying_key_extraction_cost -- --ignored --nocapture --test-threads=1
cargo test --release --locked --offline -p wallet --test performance \
  compact_trial_decryption -- --ignored --nocapture --test-threads=1
cargo test --release --locked --offline -p crypto --test build_consistency \
  poseidon_cost -- --ignored --nocapture --test-threads=1
cargo test --release --locked --offline -p storage --lib \
  nullifier_lookup_cost -- --ignored --nocapture --test-threads=1
cargo test --release --locked --offline -p chain --test chain \
  coinbase_only_block_import_timing -- --ignored --nocapture --test-threads=1
```

Persistent-media I/O, dense-block validation, full persisted wallet scanning,
async queue/lock behavior, allocation, and RSS remain unmeasured. Broad CPU,
instruction, and heap sampling tools were unavailable. Proof-class timings need
repeated isolated trials before a thread-pool change. Before another patch,
measure fixed fixtures/seeds/thread counts and compare the smallest candidate;
remove it if end-to-end improvement is absent. Allocator, PGO, linker, SIMD,
and unsafe experiments remain deferred.
