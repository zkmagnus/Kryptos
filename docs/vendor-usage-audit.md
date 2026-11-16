# Vendor usage audit

Audited on 2026-11-16 against the current root Cargo.lock, workspace manifests,
default and all-features offline Cargo metadata, local patches and the separate
`fuzz/Cargo.toml`. This is a source-usage audit, not a vulnerability or license audit.

## Results

- Vendor package directories: **594**.
- Referenced vendor packages: **579** (578 registry sources and one patched RandomX path package).
- Root resolved packages: **589**, including ten workspace crates.
- Unreferenced directories: **15**, totaling **40,358,716 logical file bytes (38.49 MiB)**.
- These candidates account for **6.50%** of vendor logical file bytes; actual disk space can differ.
- The audit itself changed no vendor sources, manifests or lockfiles. The authorized
  cleanup below subsequently removed the 15 unused directories.

## Unused source candidates

Every entry below is absent by exact package name/version from the root lockfile
and from both default and all-features resolved metadata. Active alternative
versions are listed explicitly; duplicate names alone do not imply unused code.

| Directory | Unused version | Active versions of the same package | MiB |
| --- | --- | --- | ---: |
| `vendor/windows-sys-0.52.0` | `0.52.0` | `0.61.2`, `0.59.0` | 20.56 |
| `vendor/ring` | `0.17.14` | None | 7.43 |
| `vendor/fiat-crypto` | `0.2.9` | `0.3.0` | 3.54 |
| `vendor/syn` | `3.0.9` | `1.0.109`, `2.0.119`, `3.0.10` | 2.26 |
| `vendor/winnow` | `1.0.4` | `0.7.15`, `1.0.5` | 1.29 |
| `vendor/curve25519-dalek` | `4.1.3` | `5.0.0` | 1.24 |
| `vendor/cc` | `1.10.0` | `1.11.2` | 0.55 |
| `vendor/mio` | `1.2.4` | `1.2.5` | 0.49 |
| `vendor/rand` | `0.10.3` | `0.10.4`, `0.8.8` | 0.42 |
| `vendor/toml_edit` | `0.25.17+spec-1.1.0` | `0.22.27`, `0.25.19+spec-1.1.0` | 0.35 |
| `vendor/blake2` | `0.10.6` | None | 0.15 |
| `vendor/toml_datetime` | `1.1.2+spec-1.1.0` | `0.6.11`, `1.1.3+spec-1.1.0` | 0.07 |
| `vendor/itoa` | `1.0.18` | `1.0.19` | 0.05 |
| `vendor/untrusted` | `0.9.0` | None | 0.04 |
| `vendor/errno` | `0.3.14` | `0.3.15` | 0.04 |

## Validation and limits

`cargo metadata --locked --offline --format-version 1` and the corresponding
`--all-features` command both resolved 589 packages. No platform filter was used,
so target-conditional packages were retained rather than classified by the Linux host.

A temporary directory outside the repository exposed only the 579 referenced
vendor directories using symlinks. Running all-features locked offline metadata
with that directory as `source.vendored-sources.directory` succeeded. Its package
IDs and complete resolve graph exactly matched the original metadata. The original
vendor directory remained intact. This demonstrates dependency-resolution equivalence;
a compile/test run after an actual cleanup remains the final build check.

Keep the active RandomX path patch and the locally patched bindgen source. Keep
locked Windows/macOS/WASI/wasm/Redox dependencies and transitive `socket2`, even
when the current Linux build does not compile them. `blake2` in the candidate list
is a different package from the active `blake2b_simd` used by cryptography.

## Separate fuzz dependency gap

`fuzz/` is excluded from the root workspace and has no Cargo.lock. Its locked
offline metadata command fails because `libfuzzer-sys = "0.4"` is missing from
vendor. The fuzz dependency closure was already incomplete before this audit.
Do not describe the root workspace result as proof of an offline fuzz build.
Vendoring and locking the fuzz toolchain is a separate follow-up; without that
resolution, this audit makes no claim about future fuzz dependency selections.

## Authorized cleanup

On 2026-11-16, the user authorized removing unused sources while preserving needed
dependencies. All 15 candidate directories listed above were removed. The vendor
directory now contains **579 packages**. Active local patches and target-specific
packages were retained; no manifest or lockfile update was needed.

Locked offline all-features metadata still resolves **589 packages**, with exactly
the same package IDs and dependency graph as before cleanup. The separate fuzz
dependency gap remains unchanged.

After cleanup, `CARGO_BUILD_JOBS=2 RUSTFLAGS="" cargo check --workspace
--all-targets --locked --offline` passed, as did `git diff --check`. No source or
dependency graph changed, so the full test suite was not repeated for this cleanup.
