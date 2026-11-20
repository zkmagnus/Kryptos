# Embedded Tor networking

Kryptos uses `arti-client = 0.48.0` and `tor-hsservice = 0.48.0` in the
application process. Peer and remote RPC destinations must be valid Tor v3 onion
endpoints. There is no external Tor daemon, SOCKS proxy, process supervision,
torrc generation, hostname-file lookup, direct transport, or local DNS fallback.
The compiler and toolchain are pinned to Rust 1.100.0.

The [preflight](embedded-arti-preflight.md) records the source audit and verified
upstream APIs. The workspace upgrade was authorized after the audit identified
Arti's Rust 1.92 minimum. Dependency versions and sources are locked and vendored.

## Changes by crate

| Area | Behavior |
| --- | --- |
| `p2p::address` | `NetAddr::TorV3([u8; 32])`, with Arti `HsId` text parsing and formatting; no duplicate SHA3/base32 implementation. |
| `p2p::transport` | Shared embedded Tor client, service lifecycle, isolated outbound streams, bounded inbound admission and application framing over `DataStream`. |
| `p2p::message`, `peer` | Version/genesis/nonce/services handshake includes an optional onion endpoint claim. An inbound claim remains unverified until dial-back. |
| `p2p::addrbook` | Onion identity bans/scores, own-address exclusion, persisted retry state and verified anchors. |
| `runtime::node`, `net`, `tor` | Virtual-port dispatch replaces P2P sockets. Arti status gates dialing and advertisement; failures suspend traffic and trigger backoff. |
| `runtime::rpc`, `jsonrpc`, `walletd`, `cli` | Remote access shares the Tor transport. The explicit local RPC binder accepts only `127.0.0.1`. |
| `wallet`, `crypto`, circuit/transaction crates, `protocol`, `chain`, `storage` | No application network access added; consensus, block encoding and cryptographic algorithms are unchanged. |

Snow was already removed in the previous transport migration. It is not used
elsewhere. `chacha20`, `chacha20poly1305` and `blake2b_simd` remain because the
transaction and wallet cryptography uses them.

## Addresses and handshake

The address record is `network_id=4 | length=32 | identity[32] | port[u16 BE]`.
Only Tor v3 is accepted. Unknown types, invalid lengths, truncated payloads,
invalid onion checksum/version and port zero are rejected. Names use the standard
v3 encoding supplied by `tor_hscrypto::pk::HsId`. Peer tables and gossip exclude
the local onion identity across all ports.

The application protocol is version 1. The one-round-trip handshake verifies
version, genesis/network identity and anti-self nonce, and carries service flags
plus a claimed onion endpoint. An inbound connection replies with its Version
and immediately queues its first application messages; Version receipt completes
the handshake without a Verack round trip. There is no user-agent field or
per-node version string.
Onion transport authenticates the listener. An incoming caller's claimed endpoint
does not authenticate the dialer and must not earn a verified peer record until a
successful outgoing connection to that endpoint. No static dialer authentication
key is introduced. Behavioral bans are keyed by known onion identity; anonymous
inbound connections are limited and evicted by connection behavior.

## Lifecycle, isolation and storage

One shared client is created for each node/client process. Outgoing peer streams
receive distinct isolation groups through `StreamPrefs::new_isolation_group()`.
Only parsed onion targets are passed to `connect_with_prefs`; no generic host or
IP dial path exists. Isolation separates circuits, not necessarily every guard
relay. `DataStream` implements Tokio's I/O traits directly, so no compatibility
adapter is needed. Framed writes are flushed and message bounds are preserved.

Client readiness uses `bootstrap_status`, `bootstrap_events` and
`ready_for_traffic()`. Service readiness is checked separately through the running
service's status API. Advertisement requires client readiness and Arti
`State::is_fully_reachable()`: either `Running` or `DegradedReachable`. The latter
means Arti believes the service is reachable despite reduced introduction-point
coverage or partial descriptor-upload failures. `Bootstrapping`, `Recovering`,
`DegradedUnreachable`, `Broken` and `Shutdown` remain blocked. The advertised identity comes from `RunningOnionService::onion_address`
with fixed nickname `kryptos`; no file is used as a readiness or identity source.
Lost readiness cancels/suspends dialing. Bootstrap/service failure retries with
backoff; it does not select another backend.

An online node using embedded Tor also withholds mining templates until both its
Tor client and onion service are ready. Losing readiness cancels active local
mining work and prevents local miner results from being accepted while mining is
blocked. Normal online mining also requires authenticated outbound peers,
completion of the initial header/body synchronization check, and a stable ready
period before resuming. The defaults are one outbound peer and five seconds of
stable readiness; `--mining-min-peers` and `--mining-ready-secs` configure them.
An explicitly offline embedded node can still mine without Tor.

For the first node of an intentionally bootstrapped chain, `--bootstrap-mining`
bypasses the outbound-peer requirement while retaining Tor readiness and sync
checks for connected peers. A ready onion service alone does not establish that
the node has synchronized with another chain. Configure peers with `--seed`,
`--addnode` or `--connect` when joining an existing network; there are no built-in
seed peers. See [mining readiness](mining-readiness.md). Standalone commands such
as `balance` use their own Tor client, whose readiness is independent of the
mining node's service.

Arti can initially report service state `Shutdown` before its service tasks start.
The supervisor treats that initial state as startup rather than immediately
relaunching the service. A shutdown after startup activity, or a broken state,
ends that service instance. The service startup watchdog allows 20 minutes before
retrying, accommodating Arti's descriptor publication batching and introduction
point retry timing. Client bootstrap remains a separate readiness condition:
client progress at 100% does not prove that the onion service is published or that
a peer handshake succeeded.

Storage is rooted at `<datadir>/tor`, with `state` and `cache` subdirectories.
Arti 0.48.0 places its native keystore at `<datadir>/tor/state/keystore`
(`arti-client/src/client.rs`, `create_keymgr`). It stores OpenSSH-format key
files without passphrase protection. Arti owns its internal layout; back up the
whole state directory rather than selecting undocumented filenames. Directory
creation and access use `fs-mistrust` checks, ignoring environment variables that
could disable those checks. Directories must be private (`0700` on Unix).

Stop the process before copying persistent state. Preserve the service keys and
state alongside chain and peer data: losing the onion identity key changes the
service address. Cache contents can be rebuilt. Each concurrent process needs a
separate state directory. Tor security updates now require rebuilding and releasing
the binary with updated vendored dependencies.

The local peer address book, `peers.dat`, uses the `RHPA` prefix followed by
snapshot version 1. Snapshots from earlier development builds are ignored, and
the node rebuilds its address book from discovery.

## Service protection and limits

The build enables Arti server vanguards and explicitly selects **Full** mode.
Merely enabling the feature does not automatically choose Full when a service
starts. Server PoW exists behind `hs-pow-full`, but that feature is experimental,
its runtime setting defaults off, and upstream documents LGPL dependencies.
This build does **not** enable it. Kryptos therefore applies conservative admission
limits in addition to its existing peer and queue bounds.

| Limit | Value |
| --- | --- |
| Rendezvous opening rate | 2 per second, burst 8 |
| Active rendezvous tasks | 32; release after 60 seconds without a new stream request |
| Simultaneous rendezvous and stream accepts | Shared limit 8 |
| Incoming stream queue | 32 |
| Streams per rendezvous circuit | Arti limit 8 |
| Global incoming stream opening rate | 2 per second, burst 8, shared across circuits |
| Simultaneous inbound application handshakes | 8 |
| Default total inbound peers | 32, configurable with `--max-inbound` |
| Regular outbound target | 8, configurable with `--max-outbound` |
| Persisted restart anchors | Up to 3 verified peers |
| Application handshake / outgoing Tor connect | 60 / 120 seconds |
| Keepalive interval / response deadline | 120 / 240 seconds |
| Sync body / no-progress deadline | 300 / 600 seconds |
| Outbound queue admission per peer / shared | 384 MiB / 1 GiB |

`--max-outbound 0` disables both regular dials and address-verification probes.
`--max-inbound 0` disables inbound peers and suppresses the handshake onion
endpoint claim. Inbound limits that exceed semaphore capacity are rejected during
configuration validation.

Rate/concurrency limits reject excess work and eviction favors incomplete or
misbehaving peers over established healthy peers. They protect application
resources after traffic reaches Arti; they do not provide equivalent protection
to introduction-point PoW and do not solve every Sybil/eclipse attack. Full
vanguards, anchors, bounded handshakes, retry backoff and behavioral scoring serve
different purposes and must not be described as interchangeable defenses.

## Configuration and deployment

Use `--datadir`, `--p2p-port`, repeatable `--seed`, `--addnode`, `--connect`,
`--no-seeds`, `--max-inbound` and `--max-outbound`. Built-in seed lists are empty;
operators must supply real onion endpoints. `--no-p2p` disables inbound P2P.
Library callers can select explicit offline embedding with `Config::offline`,
which disables automatic Tor startup; the CLI does not silently enter this mode.
Disabling P2P alone still starts the onion service for configured RPC endpoints.
The former `--listen`, `--socks-port`, `--tor-binary` and `--tor-external` P2P
options are removed. Local RPC options remain subject to the explicit loopback
boundary. Remote wallet/node clients use onion RPC and their own persistent
embedded client state; they do not require a SOCKS daemon.

Bridge support exists upstream through `bridge-client`, and external pluggable
transports through `pt-client`. The upstream Snowflake example launches a separate
`snowflake-client` executable. This build enables neither feature and does not
claim in-process obfs4/Snowflake support. Enabling those transports would require
a separate operational decision consistent with the self-contained deployment.

No public IP or router port forwarding is needed. The supplied Docker example
uses one container, a persistent datadir volume and no published `ports:`. See
[operations](operations.md) for commands. Actual seed onions, large-block
throughput over Tor and any bridge provisioning remain operator decisions;
consensus block limits are not changed to hide transport constraints.

## Dependencies and verification

Direct Arti packages are pinned to `=0.48.0` and licensed `MIT OR Apache-2.0`.
Supporting direct dependencies include `futures-util` (MIT OR Apache-2.0) and
`fs-mistrust` (MIT OR Apache-2.0). `tokio-socks` and its local authentication patch
are removed from the active dependency graph. Production P2P no longer depends directly on `sha3` or `data-encoding`;
they remain as dev dependencies for independent malformed-address test vectors
and as transitive dependencies elsewhere. Tokio/Arti may depend on `socket2` internally, but workspace code must not.
See [dependency maintenance](dependency-maintenance.md) for vendor preservation
and license details.

The CI source guard requires zero production `TcpStream::connect` calls and zero
`TcpListener::bind` calls outside `runtime::rpc::bind_local`. That single binder
must enforce IPv4 localhost. It also rejects local resolver/UDP APIs and retired
direct transport dependencies. Test-only fixtures are excluded explicitly. The
guard checks source policy; it is not a substitute for review of aliases, macro
expansion or upstream Arti internals. Explorer same-origin fetch and CSP
restrictions remain checked.

The isolated Arti API compile probe and workspace dependency resolution succeeded
offline; resolution with an empty Cargo home found every source inside this repo.
The resolved workspace graph contains 589 packages, including the ten workspace
crates. No selected package requires LGPL licensing exclusively; `r-efi` lists
LGPL as one alternative alongside MIT and Apache-2.0. Those checks do not
demonstrate Tor connectivity. Network unit/integration tests
use explicit in-memory/mock fixtures unless documented otherwise. The previous
548-test daemon/SOCKS result is historical and does not validate this migration.

Final verification on **2026-11-16**, with Rust **1.100.0**:

```sh
cargo fmt --all -- --check
RUSTFLAGS='' cargo clippy --workspace --all-targets --locked --offline
CARGO_BUILD_JOBS=2 RUSTFLAGS='' cargo test --workspace --locked --offline --no-fail-fast -- --test-threads=2
python3 scripts/check_tor_network.py
git diff --check
```

All commands completed successfully. Across 40 unit/integration/documentation
result groups, the workspace suite reported **545 passed, 0 failed, 9 ignored**.
The ignored tests comprise the two public-Tor exercises below, six measurement tests and one
fixed-base table generation test. Local RPC and process/signal tests ran with the required
sandbox permissions. Application networking coverage includes memory/mock Tor
routing, readiness loss, isolated peer configuration, admission bounds and
shutdown, persisted peer behavior, and sync/backpressure regressions.

Clippy exited successfully. Existing warnings remain in core crypto/protocol,
mining/scanner and related legacy code; the new networking code and its tests
introduce no Clippy diagnostics. Formatting, the direct-network source guard and
whitespace checks passed. Final metadata verification still resolved all 589
packages from this repository with offline Cargo configuration.

The authoritative local logs are
`/tmp/kryptos-embedded-workspace-tests-final.log` and
`/tmp/kryptos-embedded-clippy-verified.log`. Earlier interrupted or failed runs do
not supersede these results. These 545 passing tests describe the original mock/local
migration run; the later public-Tor successes and their separate regression
checks are described below. No Docker
build, cross-platform execution or refreshed RustSec audit is claimed. Real-network
tests require normal internet access for Arti, two independent persistent state
directories, bootstrap time and actual onion discovery; an external Tor executable
is not required.

Two optional public-Tor tests can be requested explicitly:

```sh
cargo test -p p2p --test real_tor --locked --offline -- --ignored --nocapture
cargo test -p runtime --test tor_embedded --locked --offline -- --ignored --nocapture
```

`p2p/tests/real_tor.rs` starts two embedded onion services with independent
temporary keystores and exchanges framed Ping/Pong messages. The runtime test
`two_embedded_nodes_connect_using_addnode_over_real_tor` starts two real nodes,
configures the second with the first node's onion address through `addnode`, and
checks completion of the application peer handshake. Neither test verifies mining
or block synchronization. Cargo's `--offline` restricts dependency retrieval;
these explicitly requested tests still contact the public Tor network at runtime.

Both tests remain `#[ignore]` in the default suite and were explicitly run on
**2026-11-16**. The latest public-Tor runs **both passed**:

| Test | Result and elapsed test time |
| --- | --- |
| `two_embedded_services_exchange_framed_messages` | One passed, zero failed; **337.73 seconds**. Two embedded onion services exchanged the expected framed Ping/Pong messages. |
| `two_embedded_nodes_connect_using_addnode_over_real_tor` | One passed, zero failed; **410.81 seconds**. Two actual nodes used an onion `addnode` endpoint and completed the application handshake at height zero. |

Authoritative success logs are
`/tmp/kryptos-public-tor-transport-reachable.log` and
`/tmp/kryptos-public-tor-nodes-reachable.log`. These verify public-Tor stream and
peer-handshake operation. They do not measure mining, block synchronization,
large-block throughput or production restart/state-flush durability. Both temporary
fixtures emitted an Arti state-flush error during teardown; their successful
exchange/handshake assertions do not establish clean persistent shutdown behavior.

Earlier runs each timed out after 900.01 seconds. Investigation corrected the
handling of Arti's initial `Shutdown` service state, retained a 20-minute service
startup watchdog, and replaced the overly strict `state == Running` gate with
Arti's documented `is_fully_reachable()` predicate. Client readiness is still
required. Full vanguards, isolation, blocked/unready states and onion-only routing
remain enforced. An apparently degraded service is admitted only when Arti itself
reports it as fully reachable.

After these fixes, **63 P2P regression tests passed** (61 unit tests and two
decoder tests), and **11 runtime network regressions passed**. The latter cover
unavailable-Tor gating, destination rejection, connection cancellation and queue
bounds (`/tmp/kryptos-onion-runtime-regressions.log`). Workspace Clippy, formatting,
the network source guard, whitespace
checks and offline production runtime/binary compilation also passed. Existing
legacy Clippy warnings remain. No new complete workspace test run is claimed for
these later fixes, and these 63 plus two public-network results are separate from
the historical 545-test suite. The ignored tests include bounded tracing through
`tracing` 0.1.44, already vendored; no additional registry package was introduced.

Diagnostic traces also recorded intermittent HSDir HTTP 400 descriptor rejections.
Seven saved descriptors passed Arti's outer syntax, signing-certificate signature,
descriptor signature and expiration checks. That validation did not decrypt inner
layers or test C Tor's acceptance policy, so it does not establish the cause of the
rejections. Upstream issue 2760 describes a matching symptom; this is not proof of
an identical root cause. Full output is in `/tmp/kryptos-hsdesc-validation.log`.
Independent single-service and production-wrapper probes also succeeded, but the
repository tests above provide the direct evidence for Kryptos transport and node
handshake behavior.

Actual seed identities remain operator-provided. Later RPC and block-relay
experiments passed over public Tor: the expanded empty-wallet snapshot/reconnect
test in 112.40 seconds, and four sequential coinbase-only blocks in 186.70 seconds.
See [RPC evidence](rpc-and-reorg-recovery.md) and
[block propagation measurements](block-propagation.md). These one-host smoke tests
do not establish a sustainable stale rate with competing miners. Multi-location
mining, throughput with large blocks and persistent restart behavior remain
separate operational checks, as do Docker image execution and bridge integration.

The Docker build command selects the production `runtime` binary with default
features and excludes dev dependencies. Its normal/build feature graph was checked:
`test-support`, `hs-pow-full` and `tokio-socks` are absent. The image itself has not
been built or run here.
