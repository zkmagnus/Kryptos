Kryptos implements shielded coin transfers with Halo2 proofs and ML-KEM coin
payload encryption. ML-KEM does not make the proof system or spending
authorization fully post-quantum. Network parameters are provisional and no
public bootstrap peers are built in.

Networking is Tor-only, with Arti 0.48.0 embedded in the binary. Peer and remote
RPC endpoints must be valid v3 `.onion` services. The application has no direct
transport, local DNS fallback, SOCKS dependency, or external Tor daemon. Local
RPC uses the explicitly restricted `127.0.0.1` binder; P2P streams are accepted
directly by the onion service. Preserve `<datadir>/tor/state` when backing up the
node because it contains the service identity. See the
[networking design](docs/tor-only-networking.md) for isolation and service limits.

Online mining waits for Tor, at least one authenticated outbound peer, completed
initial synchronization, and five seconds of stable readiness. The first node
of a new chain must explicitly use `--bootstrap-mining` to mine without peers.
See [mining readiness](docs/mining-readiness.md) for configuration and
[block propagation measurements](docs/block-propagation.md) for measured results
and the limits of the 120-second mainnet target.

## Build from source

See [BUILD.md](BUILD.md) for step-by-step prerequisites, offline builds,
portable binaries, tests, Docker packaging, and troubleshooting.

Install Rust through rustup; `rust-toolchain.toml` pins Rust 1.100.0, the
workspace's minimum version. Native build prerequisites are:

| Platform | Prerequisites |
| --- | --- |
| Linux x86_64 / aarch64 | C/C++ compiler, CMake, Clang/libclang, pkg-config, OpenSSL/SQLite/compression development packages |
| macOS Intel / Apple Silicon | Xcode Command Line Tools, CMake, LLVM/libclang, pkg-config, SQLite |
| Windows x86_64 MSVC | MSVC Build Tools with Desktop C++, CMake, LLVM/libclang, native SQLite libraries |

```sh
cargo build --release --locked
```

Local builds target the current CPU by default. For a generic or cross-target
artifact, override the local flags explicitly, for example
`RUSTFLAGS="" cargo build --release --locked` on POSIX shells. PowerShell:
`$env:RUSTFLAGS = "-C target-cpu=x86-64"` before building for Windows x86_64.
`CARGO_ENCODED_RUSTFLAGS` takes precedence over these settings; clear it first.
See [Build From Source](docs/operations.md#build-from-source) for installation
details, cross-builds, and the release profile trade-offs. The lockfile is
committed and Cargo uses the vendored dependencies offline.

Follow the [operations guide](docs/operations.md) for a two-node test network
over Tor, wallet recovery, and public-network readiness requirements.

Each newly issued receiving address has its own ML-KEM key. Scanning a payment
to the active address atomically selects the next address by default; automatic
receipt rotation can be disabled per wallet, and older addresses remain
scannable. A full wallet export can be recovered with `restorewallet`, preserving
address reservations and local state; see [backup and restoration](docs/wallet-backup.md).
Wallet exports currently contain plaintext secrets. The selected reorganization
limit is 50 blocks on both networks; [compatibility notes](docs/release-hardening.md)
explain why chain databases built with previous limits require a fresh sync.

Repository [CI](.github/workflows/ci.yml) checks formatting, builds, tests, and
dependency advisories. Validation limits and public-release requirements are
listed in the operations guide. See [CONTRIBUTING.md](CONTRIBUTING.md) for protocol review
requirements and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Explorer

The node's JSON-RPC HTTP endpoint serves a small local explorer at `/` (also
`/explorer`). Open the logged JSON-RPC URL in a browser and enter the node token
from `rpc.token`. The HTTP listener is enabled by default; `--rpc-http
127.0.0.1:18443` sets its address explicitly. The explorer looks up blocks by
height or hash and transactions by txid. See [the explorer notes](docs/explorer.md).

Address activity is shielded: public block data does not reveal which address
received a coin or its value. Use the wallet with the corresponding viewing
key to scan address activity.
