# Embedded Arti migration: preflight

Verified on 2026-11-16. This document records Step 0 of the embedded Tor request.
The initial preflight changed no dependency, compiler, or networking code.
The compiler upgrade below was subsequently authorized and the embedded
implementation was applied. This document preserves the original audit and
version decision; see [the implementation report](tor-only-networking.md) for
current behavior and validation limits.

## Version decision approved

The official `arti-client/latest` documentation resolves to **0.48.0**. Both
`arti-client 0.48.0` and `tor-hsservice 0.48.0` declare `rust-version = "1.92"`
and edition 2024 in their published manifests. The initial workspace used
Rust 1.90 and toolchain 1.90.0, which could not meet this requirement. On
2026-11-16 the user authorized raising the compiler and using a newer stable
release. The official stable channel manifest reports **Rust 1.100.0**, released
on **2026-11-12**; the workspace minimum and toolchain are now pinned to
**1.100 / 1.100.0**.

The following core Arti pins were subsequently applied:

```toml
arti-client = { version = "=0.48.0", default-features = false, features = [
    "tokio", "native-tls", "compression",
    "onion-service-client", "onion-service-service", "vanguards",
] }
tor-hsservice = "=0.48.0"
tor-hscrypto = "=0.48.0"
```

The selected API configuration compiled in an isolated probe. Workspace lockfile
resolution now succeeds offline, including with an empty Cargo home: 589 packages
resolve entirely from repository sources. The maximum declared minimum Rust
version among third-party packages is 1.92. Dependency edition 2024 does not
require changing the workspace's edition 2021. Full application validation is
tracked in the implementation report.

An alternative pair, `arti-client = "=0.43.0"` and
`tor-hsservice = "=0.43.0"`, declares Rust 1.89 and is therefore a candidate for
Rust 1.90. Versions 0.44.0 through 0.46.0 declare Rust 1.91, and 0.47.0 declares
Rust 1.92. This is not a claim that every patch release was audited or that the
0.43.0 dependency closure builds on 1.90. Choosing an older release would also
require repeating the API and security verification below for that release.

## Verified API and capability findings

| Request | Arti 0.48.0 finding | Integration consequence |
| --- | --- | --- |
| Client and service features | `onion-service-client` and `onion-service-service` exist; the latter enables key management. `tokio` and `native-tls` select the proposed runtime/TLS backend. | Enable explicit features rather than the broad `full` or `experimental` groups. |
| Launch service | `TorClient::launch_onion_service(config)` returns `Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>>`. `None` means disabled. | Retain the service handle and consume incoming requests; disabled or failed service must not advertise. |
| Accept streams | `tor_hsservice::handle_rend_requests` converts rendezvous requests into stream requests; `StreamRequest::accept(Connected)` asynchronously returns `DataStream`. | Inspect the requested virtual port and apply admission limits before application handshake. No application P2P TCP listener is needed. |
| Own onion identity | `RunningOnionService::onion_address()` returns `Option<HsId>`. | Advertise only the running service identity. Use a fixed nickname; do not read a hostname file. |
| Outbound | `TorClient::connect_with_prefs((onion, port), &prefs)` supports onion connections. `StreamPrefs::connect_to_onion_services` explicitly permits them. | Accept only parsed Tor v3 targets; never expose generic hostname/IP targets to this application path. |
| Peer isolation | `StreamPrefs::new_isolation_group()` creates a fresh `IsolationToken`. | Allocate a distinct group per peer; shared client ownership must not collapse isolation. This isolates circuits, not necessarily every guard relay. |
| Tokio I/O | With `tokio` enabled, `DataStream` implements Tokio `AsyncRead` and `AsyncWrite` directly. Upstream explicitly requires flushing buffered writes. | No compat adapter or multi-backend transport trait is necessary. Preserve frame bounds and flush completed messages. |
| Server vanguards | Supported by the `vanguards` feature, including service introduction, rendezvous, and directory circuit paths. Server startup does not automatically guarantee Full mode. | Configure the intended mode explicitly; do not infer protection from the feature flag alone. |
| Server PoW | `hs-pow-full` exists but is experimental. `enable_pow` defaults to false; requesting it without compile-time support fails configuration validation. Upstream states it links LGPL dependencies. | The stable-feature proposal above omits it. Strict application rate and concurrency limits are required, with this omission documented. Enabling it requires explicit feature and runtime configuration plus dependency/license review. |
| Bootstrap | `bootstrap()` is retryable; `bootstrap_status()` and `bootstrap_events()` expose `BootstrapStatus::ready_for_traffic()`. Readiness can regress. | Gate dialing continuously on API status; back off on failure and cancel pending operations when readiness is lost. |
| Service readiness | Service `status()` and `status_events()` are separate from client bootstrap. Service states include `Bootstrapping`, `Running`, degraded states, `Recovering`, and `Broken`. | Client readiness alone is insufficient evidence that the service is reachable. Gate advertisement on service readiness too. |
| Bridges | `bridge-client` supports bridges and `pt-client` supports pluggable transports. The official Snowflake example launches an external `snowflake-client`. | No claim of embedded obfs4/Snowflake support. A fully self-contained binary cannot promise those external PT implementations; bridge policy remains an explicit operational decision. |
| MSRV | Both selected core packages require Rust 1.92. | Compiler minimum raised to 1.100 with user authorization; verify the resolved dependency build. |
| State and permissions | `TorClientConfigBuilder::from_directories(state, cache)` sets storage paths and derives the keystore location. `StorageConfigBuilder` exposes state, cache, keystore, and `permissions()` (`MistrustBuilder`). | Put persistent state/cache under `<datadir>/tor`; enforce private directories and retain Arti permission checks. Back up identity keys and persistent state. |

Application admission limits only protect resources reached after Arti processes
Tor protocol traffic. They do not replace introduction-point PoW or provide an
equivalent defense against all service-level denial of service attacks.

Compilation against the downloaded source corrected one documentation assumption:
`HsId` provides `FromStr`, `AsRef<[u8; 32]>` and
`From<[u8; 32]>`; canonical formatting uses `safelog::DisplayRedacted::display_unredacted()`,
not a direct `Display` implementation. A second manual onion checksum
implementation is unnecessary.

The native keystore stores OpenSSH-format key files without passphrase support.
Provision `<datadir>/tor/state` and `<datadir>/tor/cache` under private `0700`
directories on Unix, with appropriate access restrictions on other platforms.
Back up the complete persistent state root. The subsequent source download verified `arti-client/src/client.rs` joins
`state_dir` with `keystore`, giving `<datadir>/tor/state/keystore`. Non-key state
serialization remains Arti-owned and must not be hard-coded. The `from_directories` documentation mentions `storage.keystore.path`,
but the current keystore builder has no public `path()` setter; use the verified
state/cache configuration API rather than inventing that method.

## Historical source audit and migration plan

The audit covered every workspace crate, including tests. It found no production
DNS lookup API, UDP socket, update-check client, telemetry client, `snow` use, or
direct `socket2` dependency. Tokio still depends on `socket2` transitively. Arti's
own relay sockets are an implementation dependency; the application prohibition
must cover workspace code rather than forbid Tor's underlying network access.

| File or crate | Current implementation | Required migration |
| --- | --- | --- |
| `crates/p2p/src/transport.rs` | One production `TcpStream::connect`, at line 46, to loopback SOCKS; TCP stream framing and mock SOCKS tests. | Replace with shared embedded Arti client/service streams; remove SOCKS probe/dial code and use memory-based application test fixtures. |
| `crates/p2p/src/address.rs` | TorV3 address, checksum/version validation, addrv2 wire format and property tests already exist. | Use verified `HsId` parsing/display and `[u8; 32]` conversions; preserve wire layout and rejection tests. |
| `crates/p2p/src/error.rs` | SOCKS error conversion. | Replace with relevant Arti errors. |
| `crates/p2p/src/message.rs`, `peer.rs` | Version/genesis/nonce/services handshake exists, but it does not carry an onion address claim. | Add the claim and update framing/accounting/tests; treat inbound claims as unverified until successful dial-back. |
| `crates/runtime/src/tor.rs` | Managed/external daemon, process spawn, torrc, hostname file, log-based bootstrap and SOCKS probes. | Remove daemon machinery and use Arti lifecycle/status APIs. |
| `crates/runtime/src/node.rs` | A shared binder at line 737 creates P2P, RPC, HTTP and metrics listeners. | Remove P2P binding; dispatch virtual onion ports to services. Move any permitted local RPC binding into the explicit RPC allowlist. |
| `crates/runtime/src/net.rs` | TCP listener acceptance, TCP streams and SOCKS route configuration. | Accept Arti stream requests and dial through the shared client, preserving bounded queues and cancellation. |
| `crates/runtime/src/rpc.rs` | TCP RPC serving and outbound SOCKS client. | Use shared Arti for outbound RPC, support onion streams, and centralize any permitted loopback RPC listener here. |
| `crates/runtime/src/jsonrpc.rs`, `http.rs` | TCP-specific HTTP handlers. | Adapt stream handling for onion requests and explicitly permitted local RPC. |
| `crates/runtime/src/metrics.rs` | Independent TCP metrics listener supplied by node. | Remove independent listener or integrate metrics into the permitted local RPC service. |
| `crates/runtime/src/walletd.rs` | Direct local HTTP bind at line 359, outbound node access through SOCKS. | Delegate local binding to the allowed RPC module; share embedded Tor for outgoing node access. |
| `crates/runtime/src/config.rs`, `cli.rs` | Daemon/SOCKS/P2P bind options; inbound cap configurable, outbound target fixed at eight. | Replace with virtual port and embedded state configuration; add repeated `addnode`, `no-seeds`, and configurable outbound limits. |
| `crates/runtime/src/discovery.rs`, `peers_file.rs` | Onion address book, scores/bans and three persisted verified anchors already exist. | Preserve identity-based scoring/backoff and anchor preference; integrate new configuration and admission rules. |
| Runtime/P2P unit and integration tests | Loopback, SOCKS and fake daemon fixtures. | Replace production-path assumptions; retain socket use only in tests or the allowed local RPC module; add ignored real-Tor integration. |
| `scripts/check_tor_network.py` | Requires one permitted loopback TCP dial. | Require zero production TCP dials and no bind outside the explicit local RPC allowlist. |
| `wallet`, `crypto`, `circuit`, transaction crates, `protocol`, `chain`, `storage` | No application networking. | No networking changes required. Keep consensus, block encoding and cryptographic behavior. |

Additional admission work is required: there is an existing total inbound cap and
pending-admission semaphore, but no connection-opening token bucket or distinct
application-handshake concurrency cap. Preserve healthy-peer eviction protection,
60-second application handshake, 120/240-second ping/liveness timing, 300-second
block request timeout and 600-second sync progress timeout unless testing justifies
an adjustment. Limits should apply before expensive acceptance where the API allows.

## Dependency and operational plan

- Proposed additions: exact Arti client/service/identity packages above, each
  licensed `MIT OR Apache-2.0`. Determine and vendor the complete dependency closure
  after choosing the compiler and version; no closure has been resolved yet.
- Remove direct `tokio-socks` (MIT) and its local patch. Remove direct `data-encoding`
  (MIT) and `sha3` (MIT OR Apache-2.0) only if the new identity conversion eliminates
  their application use. They may remain transitive dependencies.
- `snow` and direct `socket2` were already removed in the previous migration.
  Keep `chacha20`, `chacha20poly1305` and `blake2b_simd`: other crates use them.
- The experimental PoW feature adds `equix` and LGPL dependencies according to
  upstream. It is not part of the proposed stable-feature configuration. Full
  resolved package licenses still require inspection if it is enabled.
- Use one container, a persistent datadir volume, and no published `ports:`.
  Back up Arti identity/keystore and persistent state; losing the identity changes
  the onion address. Embedded Tor security updates require rebuilding/releasing
  the application. Public IP and router port forwarding are unnecessary for the
  onion service.
- Remaining decisions: actual seed onions, operational
  block throughput over Tor, and bridge/PT provisioning under the embedded-only
  constraint. Empty seed placeholders must not be described as working discovery.

## Validation status

At the original preflight, only published documentation, manifests, upstream
source and local application code were inspected; no build or Tor test had been
run. After authorization, the Arti API compile probe passed, dependencies were
vendored and workspace resolution passed with an empty Cargo home. Final Rust
1.100.0 verification on 2026-11-16 passed 545 tests, with zero failures and nine
ignored tests, plus formatting, the source guard and Clippy (legacy warnings
remain). The current [implementation report](tor-only-networking.md) records the
commands and distinguishes memory/mock coverage from public-Tor exercises. Earlier
explicit public-Tor attempts each timed out after 900.01 seconds. After lifecycle
and API-based readiness corrections, the latest transport Ping/Pong test passed in
337.73 seconds and the two-node `addnode` handshake test passed in 410.81 seconds.
A further 63 local P2P regression tests passed. Readiness uses client bootstrap plus
Arti's `is_fully_reachable()` (`Running` or `DegradedReachable`), preserving blocked
states and Full vanguards. These results do not verify mining/block synchronization,
throughput, persistent shutdown or Docker image execution; see the implementation
report for the teardown and descriptor-rejection diagnostic limits.

## Official sources

These are the versioned documents used for the findings. Documents were downloaded
from docs.rs; the crates.io API request returned HTTP 403.

- https://docs.rs/arti-client/latest/arti_client/
- https://docs.rs/crate/arti-client/0.48.0/source/Cargo.toml
- https://docs.rs/crate/tor-hsservice/0.48.0/source/Cargo.toml
- https://docs.rs/arti-client/0.48.0/arti_client/struct.TorClient.html
- https://docs.rs/arti-client/0.48.0/arti_client/struct.StreamPrefs.html
- https://docs.rs/arti-client/0.48.0/arti_client/struct.DataStream.html
- https://docs.rs/arti-client/0.48.0/arti_client/status/struct.BootstrapStatus.html
- https://docs.rs/tor-hsservice/0.48.0/tor_hsservice/struct.RunningOnionService.html
- https://docs.rs/tor-hsservice/0.48.0/tor_hsservice/struct.StreamRequest.html
- https://docs.rs/tor-hsservice/0.48.0/tor_hsservice/status/enum.State.html
- https://docs.rs/crate/tor-circmgr/0.48.0/source/src/hspool.rs
- https://docs.rs/crate/tor-guardmgr/0.48.0/source/src/vanguards.rs
- https://docs.rs/crate/tor-hsservice/0.48.0/source/src/config.rs
- https://docs.rs/tor-hsservice/0.48.0/tor_hsservice/
- https://docs.rs/crate/arti-client/0.48.0/source/examples/snowflake.rs
- https://docs.rs/arti-client/0.48.0/arti_client/config/struct.TorClientConfigBuilder.html
- https://docs.rs/arti-client/0.48.0/arti_client/config/struct.StorageConfigBuilder.html
- https://docs.rs/tor-hscrypto/0.48.0/tor_hscrypto/pk/struct.HsId.html
- https://docs.rs/arti-client/0.48.0/src/arti_client/config.rs.html
- https://docs.rs/tor-keymgr/0.48.0/tor_keymgr/
- https://docs.rs/crate/arti-client/0.43.0/source/Cargo.toml
- https://docs.rs/crate/tor-hsservice/0.43.0/source/Cargo.toml

Rust release source: https://static.rust-lang.org/dist/channel-rust-stable.toml
