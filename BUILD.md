# Building Rhombus

This guide covers building the node, wallet tools, and tests from this repository.
Run commands from the repository root, the directory containing `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `crates/`, and `vendor/`.

The project uses Rust **1.100.0**, edition **2021**, and vendored Cargo dependencies.
Tor is embedded through Arti. Building does not require a Tor daemon, Tor Browser,
SOCKS proxy, or running Docker. Docker is an optional packaging route.

## 1. Install native build tools

Rust alone is not sufficient: RandomX compiles C++ and assembly with CMake, and
bindgen loads libclang to generate its Rust bindings.

### Debian 13 / Ubuntu

```sh
sudo apt update
sudo apt install --yes \
  build-essential cmake clang libclang-dev pkg-config \
  libssl-dev libsqlite3-dev liblzma-dev libzstd-dev \
  ca-certificates git curl python3
```

This is the native dependency set used by the Linux build configuration. OpenSSL
supports Arti's TLS backend; the SQLite and compression development packages
cover native dependency builds. Repository verification scripts require
**Python 3.11 or newer** (`check_tor_network.py` uses `tomllib`). Check
`python3 --version` on older Ubuntu releases; the native Rust build itself does
not require running those Python scripts.

### macOS

Install Xcode Command Line Tools, then CMake and LLVM through Homebrew:

```sh
xcode-select --install
brew install cmake llvm pkg-config sqlite
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
export PKG_CONFIG_PATH="$(brew --prefix sqlite)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```

Use a Rust host toolchain matching the machine: Apple Silicon or Intel. Arti uses
platform TLS on macOS. SQLite is a native dependency with the selected features;
the path above makes its Homebrew package discoverable. See the portability job in
[CI](.github/workflows/ci.yml) for the maintained platform build matrix.

### Windows x86_64 MSVC

Install Visual Studio Build Tools with the **Desktop development with C++**
workload and Windows SDK, plus CMake and LLVM/libclang. Open a Developer PowerShell
with the MSVC tools available. Set `LIBCLANG_PATH` to the directory containing
`libclang.dll`; for the standard LLVM installation:

```powershell
$env:LIBCLANG_PATH = "$env:ProgramFiles\LLVM\bin"
```

Also provide an MSVC-compatible SQLite development installation, including its
header, import library, and runtime DLL. The current Arti dependency configuration
does not enable bundled SQLite. The vendored `libsqlite3-sys` supports vcpkg
discovery; alternatively, set the paths explicitly. For example, replace
`C:\deps\sqlite` below with your actual installation directory:

```powershell
$env:SQLITE3_INCLUDE_DIR = "C:\deps\sqlite\include"
$env:SQLITE3_LIB_DIR = "C:\deps\sqlite\lib"
$env:PATH = "C:\deps\sqlite\bin;$env:PATH"
```

The import library must match the MSVC x86_64 target; a `sqlite3` command-line
executable alone is insufficient. The native discovery code checks for SQLite
3.34.1 or newer through pkg-config when available.

Use the `x86_64-pc-windows-msvc` Rust host toolchain. The build commands below use
POSIX syntax unless a PowerShell alternative is shown.

## 2. Install and select the pinned Rust toolchain

Install rustup for your operating system if it is not already available. Run the
following as your normal user, without `sudo`:

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt,clippy
rustup show active-toolchain
rustc --version
cargo --version
```

Inside this repository, `rust-toolchain.toml` selects **1.100.0** automatically.
A different global `stable` toolchain can remain installed. Outside the repository,
Rustup may select that other toolchain instead.

For editor support, optionally install components for the same pinned toolchain:

```sh
rustup component add --toolchain 1.100.0 rust-analyzer rust-src
rust-analyzer --version
```

## 3. Verify the offline dependency setup

Keep the entire `vendor/` directory and `.cargo/config.toml` with the source tree.
Cargo replaces crates.io with these local sources and defaults to offline mode.

```sh
cargo metadata --locked --offline --format-version 1 > /dev/null
```

PowerShell equivalent:

```powershell
cargo metadata --locked --offline --format-version 1 | Out-Null
```

`--locked` rejects dependency resolution that would require changing `Cargo.lock`.
`--offline` prevents Cargo from retrieving dependencies from the network. Install
Rust and native system packages before disconnecting: vendoring does not include
the compiler, OS packages, or Docker base images.

The vendor tree contains local RandomX and bindgen fixes. Preserve it instead of
replacing it with an unreviewed `cargo vendor` run. Dependency maintenance is
covered in [dependency-maintenance.md](docs/dependency-maintenance.md).

The excluded `fuzz/` project has a separate dependency gap: `libfuzzer-sys` is not
vendored. Normal workspace builds and tests do not build it. Do not assume that
the commands here also prepare an offline fuzzing environment.

## 4. Build release binaries

Choose one of the following CPU configurations. Two Cargo build jobs are a useful
starting point for limiting simultaneous compiler processes; reduce this to one
if memory is tight.

### Build for this machine

The repository sets `-C target-cpu=native` for local builds. To use that setting,
clear environment overrides before building:

```sh
unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS
CARGO_BUILD_JOBS=2 cargo build --release --locked --offline -p runtime --bins
```

### Build for other machines with the same target platform

Use the target's default CPU baseline instead of the build machine's CPU features:

```sh
unset CARGO_ENCODED_RUSTFLAGS
RUSTFLAGS="" CARGO_BUILD_JOBS=2 cargo build --release --locked --offline -p runtime --bins
```

PowerShell, for Windows x86_64:

```powershell
Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
$env:RUSTFLAGS = "-C target-cpu=x86-64"
$env:CARGO_BUILD_JOBS = "2"
cargo build --release --locked --offline -p runtime --bins
```

An explicit x86-64 baseline also works in PowerShell versions where assigning an
empty environment variable removes it. `CARGO_ENCODED_RUSTFLAGS`, if present,
overrides `RUSTFLAGS`, which is why these examples clear it first.

A CPU baseline does not make a binary universal or fully static. The destination
must match the operating system and architecture and provide compatible runtime
libraries. For Linux distribution artifacts, account for the libc and shared
library versions of the build environment. These flags control Rust codegen;
native dependency requirements still apply. In particular, the vendored RandomX
CMake configuration uses `-march=armv8-a+crypto` for its default aarch64 build, so
do not assume that clearing `RUSTFLAGS` makes it compatible with every ARM CPU.

Release builds use optimization level 3, fat LTO, and one codegen unit. The final
link can take time and memory even with a low Cargo job count.

### Output files

| Binary | Default release path | Purpose |
| --- | --- | --- |
| `rhombus` | `target/release/rhombus` | Node and wallet command-line interface |
| `wallet` | `target/release/wallet` | Wallet RPC daemon |
| `rhomscan` | `target/release/rhomscan` | Scan a local chain database into a wallet |

Windows adds `.exe`. An explicit `--target` adds the target triple beneath
`target/`; `CARGO_TARGET_DIR` changes the output root.

Check that the binaries start without opening a node or modifying a wallet:

```sh
./target/release/rhombus --help
./target/release/wallet --help
./target/release/rhomscan --help
```

To build only the node/CLI executable:

```sh
CARGO_BUILD_JOBS=2 cargo build --release --locked --offline -p runtime --bin rhombus
```

For running nodes, choosing onion peers, creating wallets, and recovery, follow
the [operations guide](docs/operations.md). Built-in seed lists are empty, so a
successful build alone does not connect a node to an existing Rhombus network.

Keep production builds on the default features used above. `--all-features`
enables P2P `test-support`, which is intended for fixtures.

## 5. Development checks and tests

A compilation check avoids the final binary link:

```sh
CARGO_BUILD_JOBS=2 cargo check --workspace --all-targets --locked --offline
```

For normal development executables:

```sh
CARGO_BUILD_JOBS=2 cargo build --locked --offline -p runtime --bins
```

These executables are written under `target/debug/` by default.

### Keeping development builds small

The workspace's `dev` and `test` profiles disable debug information and
incremental compilation. This avoids full Rust debug symbols in each test
executable and the additional incremental compiler cache. Changed crates may
take longer to recompile; Cargo still reuses unchanged compiled dependencies.
Rust debug assertions and overflow checks remain enabled. Test optimization
stays at level 1. See [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
for these settings and their overrides.

During iteration, check and test the affected package before running the full
workspace suite:

```sh
cargo check -p wallet --locked --offline
cargo test -p wallet --lib --locked --offline -- --test-threads=2
```

Reuse one target directory and consistent CPU flags for routine commands; the
default directory is `target/`. Different profiles, features, CPU flags and
target directories can retain additional artifacts. Avoid cleaning after every
test, which forces dependencies to compile again. These settings reduce cache
growth but do not impose a disk quota or remove existing artifacts.

For a debugging session, explicitly enable full debug information, for example
on POSIX shells:

```sh
CARGO_PROFILE_DEV_DEBUG=2 CARGO_PROFILE_TEST_DEBUG=2 \
cargo test -p wallet --lib --locked --offline -- --test-threads=2
```

PowerShell: set `$env:CARGO_PROFILE_DEV_DEBUG = "2"` and
`$env:CARGO_PROFILE_TEST_DEBUG = "2"` before the command, then remove both
environment variables afterwards to restore the smaller defaults.

Run the repository checks with portable CPU flags:

```sh
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS=""
export CARGO_BUILD_JOBS=2
cargo fmt --all -- --check
python3 scripts/check_tor_network.py
python3 scripts/check_seed_vectors.py
cargo clippy --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline -- --test-threads=2
```

Proof generation and RandomX tests can be slow. Limiting test threads reduces
simultaneous proving/mining work. Some runtime tests bind RPC loopback sockets or
exercise process signals; a sandbox denying these operations can cause failures.
Clippy currently reports existing warnings; a successful command is not a claim
of a warning-free codebase.

The ordinary suite does not require public Tor connectivity. The public-network
tests are ignored by default and can be requested separately:

```sh
RUSTFLAGS="" CARGO_BUILD_JOBS=2 cargo test -p p2p --test real_tor --locked --offline -- --ignored --nocapture
RUSTFLAGS="" CARGO_BUILD_JOBS=2 cargo test -p runtime --test tor_embedded --locked --offline -- --ignored --nocapture
```

These tests contact Tor relays at runtime even though Cargo uses `--offline`.
They allow up to 15 minutes for service readiness before the exchange/handshake
phase. See [Tor networking](docs/tor-only-networking.md) for verified results and
remaining coverage limits. Avoid using an unrestricted `--ignored` on the entire
workspace: it also includes measurements and a table-generation utility.

## 6. Optional Docker build

With Docker Engine, Buildx, and Compose available, build from the repository root:

```sh
sudo docker build --tag rhombus:local .
sudo docker run --rm rhombus:local --help
```

Omit `sudo` if your Docker setup already allows access as your normal user. The
Dockerfile builds a portable release `rhombus` executable in a Rust 1.100.0 builder
and copies it into a Debian Bookworm runtime image with its runtime libraries.
Of the workspace executables, the image packages only `rhombus`; the separate `wallet` and `rhomscan` binaries are not packaged.

Docker needs network access for base images and `apt` packages unless these are
provided locally. Only the Cargo dependency build inside the image is offline.
The supplied Docker configuration has not yet been validated by an image build
in this development session; source-build and Tor-test results do not establish
container readiness.

To build the Compose service and inspect its configuration without starting it:

```sh
sudo docker compose config
sudo docker compose build
```

For running the container, see [operations](docs/operations.md). The supplied
Compose file uses a persistent datadir volume and publishes no host ports.

## 7. Cross-compilation

Installing a Rust target is only one part of a cross build. For example:

```sh
rustup target add --toolchain 1.100.0 aarch64-unknown-linux-gnu
```

Before building, provide a target C/C++ compiler, linker, sysroot, and compatible
native dependencies. RandomX and other native libraries require that target
configuration as well. Once those are configured:

```sh
unset CARGO_ENCODED_RUSTFLAGS
RUSTFLAGS="" CARGO_BUILD_JOBS=2 cargo build --release --locked --offline \
  --target aarch64-unknown-linux-gnu -p runtime --bins
```

The outputs are under `target/aarch64-unknown-linux-gnu/release/`. The CI portability
jobs build on native runners; they do not prove that an arbitrary cross toolchain
is configured correctly. macOS and Windows commands in this guide have not
been executed as part of writing this document.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Wrong Rust version or missing `rust-analyzer` | Run inside the repo and inspect `rustup show active-toolchain`. Install components for `1.100.0`, not only for global `stable`. |
| `Unable to find libclang` | Install libclang development files and set `LIBCLANG_PATH` to the directory containing its shared library. On macOS, use the Homebrew LLVM path above. |
| CMake, C++ compiler, or linker missing | Install the native prerequisites for the target platform; on Windows, use a Developer PowerShell with MSVC available. |
| OpenSSL/pkg-config discovery fails on Linux | Check `libssl-dev` and `pkg-config`. For cross builds, check target libraries and sysroot rather than pointing at host libraries. |
| Cargo cannot find a package offline | Check that the complete vendor tree, lockfile, and `.cargo/config.toml` match this checkout. The separate fuzz dependency gap is documented above. |
| `--locked` reports that the lockfile needs updating | Check for inconsistent manifest/lockfile edits. Dependency updates require a coordinated vendor update; dropping `--locked` is not a build repair. |
| Compiler/linker is killed or runs out of memory | Retry with `CARGO_BUILD_JOBS=1` and close other heavy builds. For iteration, use `cargo check` or a debug build instead of release LTO. |
| Binary fails with an illegal instruction on another CPU | Rebuild using the portable CPU configuration above and check native RandomX architecture requirements. |
| A shared library is missing when starting a copied binary | Install the required runtime library on the destination, or package against a compatible runtime image. |
| Tests fail with `PermissionDenied` on loopback sockets or signals | Run the relevant tests in an environment that permits their local RPC/process fixtures. |
| Onion service is still bootstrapping | This is a runtime networking issue, not evidence that compilation failed. Inspect the Arti test logs and the networking guide. |

Do not run Cargo with `sudo`. Use elevated permissions only for system package
installation or Docker access when your installation requires them.
