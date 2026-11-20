# Running and checking Kryptos

Kryptos is an experimental implementation. The `main` parameters remain
provisional; neither `main` nor `test` has built-in bootstrap peers. The examples
below create a test network over Tor. They do not activate a public release.

## Build From Source

The repository pins Rust 1.100.0 in `rust-toolchain.toml`; install the `x86_64`
or `aarch64` host toolchain appropriate for the machine. `Cargo.lock` is
committed, and Cargo is configured to use the checked-in vendor directory
offline. RandomX builds vendored C++ and assembly with CMake. Bindgen also needs
libclang at build time.

Install the native build prerequisites for your platform:

| Platform | Prerequisites |
| --- | --- |
| Linux x86_64 / aarch64 | C and C++ compilers, CMake, Clang, libclang, and pkg-config; on Debian/Ubuntu: `build-essential cmake clang libclang-dev pkg-config libssl-dev libsqlite3-dev liblzma-dev libzstd-dev` |
| macOS Intel / Apple Silicon | Xcode Command Line Tools, CMake, LLVM/libclang; with Homebrew: `xcode-select --install` then `brew install cmake llvm` |
| Windows x86_64 MSVC | Visual Studio Build Tools with the Desktop development with C++ workload, CMake, and LLVM/libclang; make LLVM's `bin` directory available to bindgen through `LIBCLANG_PATH` |

Build the node and wallet command-line binaries from the repository root:

```sh
cargo build --release --locked -p runtime --bins
```

Local builds use `-C target-cpu=native` so Rust code can use the build
machine's CPU features. This produces a binary intended for that machine. To
make a portable release binary or cross-compile, clear `RUSTFLAGS`, which
overrides the repository's Cargo configuration:

```sh
RUSTFLAGS="" cargo build --release --locked -p runtime --bins
RUSTFLAGS="" cargo build --release --locked --target aarch64-unknown-linux-gnu -p runtime --bins
```

In PowerShell on Windows x86_64, set
`$env:RUSTFLAGS = "-C target-cpu=x86-64"` before running Cargo. This explicit
baseline also works on PowerShell versions before 7.5, where assigning an empty
string removes the variable and would restore the repository's native setting.
`CARGO_ENCODED_RUSTFLAGS`, when set, takes precedence over both `RUSTFLAGS` and
the Cargo configuration; unset it before applying these overrides. On
PowerShell use `Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue`;
on POSIX shells use `unset CARGO_ENCODED_RUSTFLAGS`.

Cross-compilation also needs a C/C++ cross toolchain and linker for the target
because RandomX is built by CMake.

Release builds use `opt-level=3`, fat LTO, and one codegen unit. LTO can improve
runtime and code size at the cost of clean-build/link time; a single codegen
unit can further limit parallel compile time. These settings are retained until
runtime and build-time measurements justify changing them. Panic strategy and
symbol stripping remain at Cargo's defaults.

Run commands from the repository root. The binaries are
`target/release/kryptos` (node and wallet CLI), `target/release/wallet` (wallet
RPC daemon), and `target/release/rhomscan` (local database scanner). The `wallet` binary
currently prints `Kryptos-wallet-rpc` in its help text.

## Test network over embedded Tor

Tor is embedded through Arti; no daemon, SOCKS listener or router port forwarding
is needed. Give each node and concurrent standalone client a separate datadir.
Arti stores private persistent state and identity keys below `<datadir>/tor/state`
and caches below `<datadir>/tor/cache`. The service nickname is fixed. Back up the
state directory with the node stopped; losing its identity key changes the onion
address. Directories must remain private (`0700` on Unix).

All peers and seeds must be valid v3 onion endpoints. Bootstrap and service
readiness come from Arti APIs; dialing/advertisement wait for readiness and failures
retry with backoff. The endpoint reported when the service becomes ready is the
one to share with other nodes. There is no hostname file to read.

Create a test wallet and keep its printed seed phrase private:

```sh
mkdir -p local-test
chmod 700 local-test
target/release/kryptos create --network test --wallet local-test/wallet.redb
```

In the first terminal, start a mining node. The address command prints its public
payment address:

```sh
KRYPTOS_TEST_ADDRESS="$(target/release/kryptos address --network test --wallet local-test/wallet.redb)"
target/release/kryptos run --network test --datadir local-test/node-a \
  --p2p-port 19000 --rpc 127.0.0.1:18444 --rpc-http 127.0.0.1:18443 \
  --mine "$KRYPTOS_TEST_ADDRESS" --mining-threads 1 --bootstrap-mining
```

With `--mine`, the online node waits for both its embedded Tor client and onion
service to become ready before issuing mining work. If Tor loses readiness, the
node pauses active local mining and rejects local miner results while blocked.
Normal online mining also requires at least one authenticated outbound peer,
initial header/body synchronization, and a stable ready period before work
resumes. Configure these with `--mining-min-peers` (default 1) and
`--mining-ready-secs` (default 5). Explicitly offline embedded nodes can still
mine without Tor.

The example uses `--bootstrap-mining` because node A intentionally starts this
test chain without peers. When joining an existing chain, omit that flag and
configure `--seed`, `--addnode` or `--connect`. There are no built-in seed peers,
and `embedded Tor ready` alone does not establish chain synchronization. See
[mining readiness](mining-readiness.md) for the bootstrap and recovery policy.

After service readiness, copy node A's reported onion hostname into
`KRYPTOS_ONION_A`. The placeholder below is deliberately not a working peer:

```sh
KRYPTOS_ONION_A='<node-a-v3-hostname>.onion'
target/release/kryptos run --network test --datadir local-test/node-b \
  --p2p-port 19000 --addnode "$KRYPTOS_ONION_A:19000" \
  --rpc 127.0.0.1:18544 --rpc-http 127.0.0.1:18543
```

Virtual onion ports can be identical between nodes; they are not P2P socket
bindings. Local RPC listeners on the same machine still require distinct local
ports. The node exposes configured RPC ports on its onion service as well, with
the same token authentication. Copy node B's reported onion hostname when needed.

A standalone CLI starts its own embedded Tor client and waits for that client's
readiness independently of the node. Use a separate client datadir so it never
opens another process's Arti state:

```sh
target/release/kryptos status --rpc "$KRYPTOS_ONION_A:18444" \
  --datadir local-test/status-client --rpc-token-file local-test/node-a/rpc.token
target/release/kryptos balance --wallet local-test/wallet.redb \
  --rpc "$KRYPTOS_ONION_A:18444" --datadir local-test/wallet-client \
  --rpc-token-file local-test/node-a/rpc.token
```

Compare tip heights/hashes after allowing time for Tor bootstrap and block
propagation. A continuously mining tip may move between requests. For the local
explorer, open the logged JSON-RPC address and supply the node token. Its browser
requests stay on the same origin. See [the explorer guide](explorer.md).

Stop nodes with Ctrl-C or SIGTERM and wait for exit before copying databases or
Arti state. Keep test/main wallet files separate; wallets are bound to their
network's genesis. A service-ready log confirms Arti's reported readiness, not
successful synchronization with an independent peer.

## Wallet daemon

After the CLI releases the wallet database, run its daemon with independent Tor
state:

```sh
target/release/wallet --network test --wallet local-test/wallet.redb \
  --node "$KRYPTOS_ONION_A:18444" --datadir local-test/wallet-daemon \
  --node-token-file local-test/node-a/rpc.token --listen 127.0.0.1:18447
```

The generated `wallet-rpc.token` lives beside the wallet and differs from the node
token. Do not open the same wallet concurrently from another process. The local
wallet HTTP server uses the allowed loopback RPC binder; outgoing node access uses
embedded Tor.

## Joining an operator-managed test network

Agree on source revision, genesis and consensus parameters before joining. Supply
repeatable `--seed`, `--addnode` or `--connect` onion endpoints. `--no-seeds` disables
built-in seeds; their lists are currently empty. `--max-outbound` defaults to eight,
`--max-inbound` to 32, and `--no-p2p` disables inbound P2P. No public bootstrap service
is provided. Online mining requires synced outbound peers unless the operator
explicitly selects `--bootstrap-mining`; height growth under bootstrap mode alone
does not prove membership in another network.

The old P2P `--listen`, `--socks-port`, `--tor-binary`, `--tor-external`, `--proxy`
and `--advertise` flags are removed. There is no external Tor configuration to
maintain. The independent metrics socket and its `--metrics` flag are removed. Local RPC
addresses are limited to `127.0.0.1`.

Full vanguards are explicitly enabled. Experimental onion-service PoW is disabled;
strict rendezvous and handshake admission limits mitigate application load but do
not replace PoW at introduction points. See [the limits](tor-only-networking.md#service-protection-and-limits).
Arti supports bridges upstream, but this binary does not enable bridge/PT features;
obfs4/Snowflake would need separately provisioned transport executables and a
separate integration decision. Tor security fixes require a binary rebuild/release.
Measure large-block throughput over real Tor before selecting operational limits.

## Container

The example uses one container with a persistent volume and no published ports:

```sh
docker compose build
docker compose up
```

Add real onion `--addnode` arguments to the Compose command to join another node.
The example defaults to the provisional test network. Back up the `node-data`
volume with the service stopped; it includes the chain, RPC token, peer book and
Arti identity. No external Tor container is used. Container building and real Tor
connectivity must be tested on the deployment host; the configuration itself does
not establish either result.

A source review on 2026-11-16 confirmed the configuration selects a two-stage
production node build, declares Linux native dependencies, runs as UID/GID
10001, keeps `/data` private and persists it through one named volume. The build
context allows only manifests, Cargo configuration, source crates and vendor inputs;
runtime state and credentials are excluded. The Dockerfile copies those build
inputs explicitly instead of copying an entire working directory. Docker was
subsequently installed by the operator, but this image has not been built or
started during the verification described here.
Cargo's `--offline` applies to vendored Rust dependencies; downloading base images,
OS packages or missing compiler components still needs the relevant build access.
If replacing the named volume with a host bind mount, provide a directory owned by
the container's UID/GID with private permissions and test access before deployment.

## Wallet address rotation

Use the wallet's current receive address for new payment requests. By default,
it remains stable until the wallet scans a payment to it or prepares a new
outgoing transaction. When receipt rotation is enabled, the scan immediately
persists a fresh diversified address; a send retires the selection and the next
receive-address request allocates its replacement. Previously shared addresses
remain valid and scanned; another payment to an older address does not invalidate
an unrelated unused current one.
`getreceiveaddress` returns the current `{index, address, exhausted}` result.
`getwalletinfo` also reports `receive_address`, `receive_address_index` and
`address_rotation_exhausted`. With receipt rotation enabled, scans persist the
next address.
After a send retires the selection, these methods allocate its replacement;
repeated calls reuse the persisted current value.
`getnewaddress` explicitly allocates a new address and selects it as current.
The CLI `address` command prints that same current selection.

Receipt rotation can be disabled per wallet without disabling scanning. Use
`setreceiveaddressrotation` with a boolean `enabled` parameter through Wallet
RPC, or use the CLI while the wallet daemon is stopped:

```sh
kryptos set-receive-rotation --network main --wallet wallet.redb --enabled false
```

The setting is saved in wallet metadata and version-1 plaintext backups.
It defaults to enabled when the field is absent. Manual `getnewaddress` and the
existing send/change address behavior are unchanged.

Sending uses the recipient address supplied by the caller. Change, when present,
goes to a freshly reserved wallet address. Reservations are durable before proof
construction, so an interrupted or failed build can consume an index without a
broadcast transaction. Rebroadcasting saved transaction bytes does not allocate
another address, and reorganization does not rewind the allocation counter.

Receive, manual and change addresses share the 4096-index allocation limit.
At exhaustion, receive/status RPC returns null address fields and an explicit
flag, while manual allocation or change construction requiring another index
fails. Existing-address scanning continues. Keep the
highest reserved index, including internal change keys and unused reservations,
with recovery records. A miner continues using its configured payout address;
wallet rotation does not rewrite a running node's payout configuration.
Automatic rotation also increases the number of ML-KEM keys
tried during scanning. See [address rotation](address-rotation.md) for semantics,
limits and compatibility with historical addresses. The rotation change passed
157 unique wallet/runtime tests on 2026-11-16, with one performance benchmark
ignored, plus workspace-wide compilation and Clippy. See the
[rotation validation scope](address-rotation.md#validation); these targeted results
are separate from the embedded-network migration's workspace test run.

## Backup and recovery

Keep the seed phrase and account number offline. Wallet databases and JSON
exports contain plaintext secrets even though Unix files are owner-only.
Create an export with the wallet daemon stopped:

```sh
target/release/kryptos backupwallet --network test \
  --wallet local-test/wallet.redb --out local-test/wallet-backup.json
```

Restore a version-1 plaintext JSON export into a **new** wallet file:

```sh
target/release/kryptos restorewallet --network test \
  --backup local-test/wallet-backup.json --wallet local-test/restored.redb
```

Both commands refuse to replace an existing destination and publish only a
complete file. Restoration checks the selected network and validates keys,
address allocation, coin records, witnesses, scan history and operations before
publishing the database. The derived nullifier index is rebuilt. Labels,
pending-operation history, receiving state and reserved address indices are
preserved; restoring a JSON backup does not require `--restore-through`.
Synchronize the restored wallet before spending. Restore only your own trusted
backup: validation is not authentication of the backup or a chain revalidation.
See [wallet backups](wallet-backup.md) for guarantees and limitations.

A stopped wallet database copy also preserves local state. To rebuild
coin state from a phrase, supply the highest previously reserved address
index with `--restore-through` (inclusive, `0..4095`). This bound is required
because a seed does not reveal which indices were reserved for receiving or
change, and the wallet deliberately does not guess a gap limit. Include unpaid
reservations left by interrupted or failed transaction builds. For example, if indices
0 through 7 may have been used:

```sh
target/release/kryptos create --network test --wallet local-test/restored.redb \
  --phrase --account 0 --restore-through 7
target/release/kryptos balance --wallet local-test/restored.redb \
  --rpc "$KRYPTOS_ONION_A:18444" --datadir local-test/wallet-client \
  --rpc-token-file local-test/node-a/rpc.token
```

The `--sk` import option also requires `--restore-through`. It accepts the
spending key as a command argument, which can expose it through process
inspection or shell history; prefer phrase recovery in a private terminal
when a phrase is available. Fresh seed creation rejects `--restore-through`.

The restore command prints `scan_address_indices` and `next_address_index`.
Record the highest reserved index in the backup procedure. A normal wallet keeps
its durable range and extends it as new addresses are issued, up to 4096
separate ML-KEM keys. To recover a larger historical range later, create a new
wallet file with a higher bound and rescan from genesis; increasing the bound
does not silently apply only to future blocks. Legacy shared-key address recovery
and scanning are no longer supported. Wallets with missing address-scheme
metadata or a legacy shared-key allocation range are rejected. Current addresses
use separate ML-KEM keys; reusing one address remains linkable.

The automatic wallet API only issues per-address indices `0..4095`, so every
wallet-created address remains within the supported phrase-recovery bound.
Low-level library callers that derive arbitrary
indices must supply and preserve their own recovery range.
Do not downgrade a migrated wallet: older receivers cannot discover payments
to the new per-address keys. The address and transaction byte layouts are
unchanged, so existing senders can pay a newly issued address. See the
[derivation and compatibility design](diversified-ml-kem-addresses.md).

`--phrase` reads `SEED_PHRASE` if set, otherwise prompts on standard input;
the prompt is not a hidden-password input. Use a private terminal and do not
paste secrets into shell command arguments, recordings, or logs. A rescan
rebuilds on-chain coin state, not all local labels or pending-operation history.
Address allocation and current-receive state are durable across reorganization;
chain rollback does not make an already published address fresh again.
Keep the original wallet and binary when testing restoration across revisions,
and verify the pinned seed compatibility vectors before deploying an upgrade.

The wallet daemon's `getwalletinfo` reports the persisted
`address_scan_start`, `address_scan_end_exclusive`, `next_address_index`,
`legacy_address_scanning`, and `max_separate_address_keys` values. Use these
fields to confirm the recovery range before initiating a rescan. Scanning cost
grows with the number of address keys times the number of outputs; an oversized
range is rejected rather than silently truncated.
`getaddressinfo` also reports `scan_covered`: an address may belong to the wallet
while its new key lies outside the configured scan range. Receipt records keep
the address scheme; legacy coin addresses cannot be reconstructed.
Version-1 plaintext JSON backups include this metadata and the extended coin
records.

An interrupted reorg has an automatic durable recovery path: restart with the
same compatible updated binary and allow recovery to finish. See
[reorg recovery](rpc-and-reorg-recovery.md). For database corruption, preserve
a stopped copy before diagnosis. For an intentional incompatible development
reset, use a fresh chain directory only after confirming the new revision and
genesis with operators; a resync cannot restore coins from an abandoned genesis.
Never delete a wallet as part of a chain reset.

## Optional public-Tor checks

The default workspace suite does not contact public Tor. To request the ignored
transport and real-node handshake checks explicitly:

```sh
cargo test -p p2p --test real_tor --locked --offline -- --ignored --nocapture
cargo test -p runtime --test tor_embedded --locked --offline -- --ignored --nocapture
```

The first exchanges Ping/Pong through two embedded onion services. The second
runs two actual nodes and verifies an `addnode` connection reaches application
handshake readiness. Both use separate temporary keystores. They require internet
access for Arti even with Cargo's dependency `--offline` flag, and neither verifies
mining or block synchronization. Both remain ignored by default, but the latest
explicit runs on 2026-11-16 **passed**: transport Ping/Pong in **337.73 seconds** and
two-node `addnode` handshake in **410.81 seconds**. Earlier 900-second timeouts were
investigated; readiness now uses Arti's `is_fully_reachable()` predicate with client
bootstrap required, including the documented `DegradedReachable` state.

These successes do not establish mining, block sync, large-block throughput or
clean persistent shutdown. Temporary fixture teardown emitted Arti state-flush
errors, so persistence/restart behavior still needs its own verification. See
[the full results and limits](tor-only-networking.md#dependencies-and-verification).
Use the earlier two-node mining procedure to evaluate synchronization and real
throughput separately; actual public seed identities remain operator-provided.

The additional RPC and block-relay experiments now cover wallet snapshot
reads/reconnects and a small sequence of validated blocks over public Tor:

```sh
cargo test -p runtime --test rpc_real_tor --locked --offline -- --ignored --nocapture
cargo test -p runtime --test propagation public_tor_two_node_relay_reports_timings --locked --offline -- --ignored --nocapture
```

The expanded RPC wallet test passed in 112.40 seconds; the four-block public-Tor
relay test passed in 186.70 seconds. These are fresh temporary fixtures on one
host, not a production wallet recovery or a multi-location competing-miner
benchmark. See [RPC recovery](rpc-and-reorg-recovery.md) and
[measured relay results](block-propagation.md) for the tested paths and limits.

## Checks and public-release requirements

[CI](../.github/workflows/ci.yml) runs formatting, all-target compilation,
workspace tests (including integration and documentation tests), and a current
RustSec lockfile audit. It runs on pushes, pull requests, manual dispatch, and
weekly for newly published advisories. The workflows have read-only repository
permissions. They neither publish binaries nor activate network rules.

[Dependabot](../.github/dependabot.yml) proposes weekly updates for the root
Cargo workspace and GitHub Actions. Updates still need review and passing
checks; no automatic merge is configured. The pinned Rust and `cargo-audit`
versions in shell commands need deliberate maintainer updates because these
are not GitHub Action dependencies.

Equivalent checks:

```sh
RUSTFLAGS="" cargo fmt --all -- --check
RUSTFLAGS="" cargo check --workspace --all-targets --locked
RUSTFLAGS="" cargo test --workspace --locked -- --test-threads=2
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings
```

Proof and RandomX tests need more CPU/memory than parser-only tests. Local RPC integration tests need loopback TCP binding permissions. Embedded P2P
fixtures use in-memory streams; real Tor tests must be requested explicitly. Measurement/table
regeneration tests marked `#[ignore]` are separate explicit tasks, not run by
the default suite. The fuzz target in `fuzz/` is not a continuous fuzzing service.

The embedded migration's final Rust 1.100.0 workspace run on 2026-11-16 passed:
**545 tests passed, 0 failed, 9 ignored** across 40 result groups. The ignored tests
are two public-Tor exercises, six measurement tests and one fixed-base table
generation test. Formatting, the network
source guard, whitespace checks and Clippy passed; Clippy still reports existing
legacy warnings, with no new networking diagnostics. See the
[verification report](tor-only-networking.md#dependencies-and-verification).

Historical advisory findings and the daemon-era test results must not be confused
with current validation. A refreshed RustSec audit of the embedded dependency
graph is still required. CI retains `cargo audit --deny warnings`, including
yanked release checking. A cached or older successful audit is not current coverage.

Before a public release, maintainers must resolve failing checks, obtain the
independent protocol and cryptography reviews required by
[CONTRIBUTING.md](../CONTRIBUTING.md), publish the selected revision/network
parameters and bootstrap endpoints, test restore/reorg/upgrade procedures, and
measure worst-case proof validation, wallet scanning, RAM, bandwidth, and disk
growth. Enable private vulnerability reporting and require the CI jobs in
branch protection through the hosting settings. Adding these files cannot
enable those settings, provide independent reviewers, or establish a public
bootstrap service; these remain operator/maintainer tasks.
