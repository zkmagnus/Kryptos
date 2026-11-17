# Tor transport settings

Rhombus uses embedded Arti 0.48.0 for both client and anonymous onion service.
The P2P destination type is exclusively `NetAddr::TorV3`; there is no direct-IP,
DNS or alternative transport fallback. Full vanguards remain enabled. None of
the following options shortens paths or enables a non-anonymous service.

The settings live in `p2p::transport::TorSettings`, are available through
`runtime::tor::TorConfig::settings`, and have fixed defaults shared by all nodes.
Durations supplied through the CLI are seconds.

| CLI option | Default | Behavior |
| --- | ---: | --- |
| `--connect-timeout` | 60 | Total onion destination connection deadline; also passed to Arti's stream connect timeout. |
| `--handshake-timeout` | 60 | Application Version exchange and incoming rendezvous acceptance deadline. |
| `--idle-timeout` | 900 | Maximum silence while waiting for the first byte of a peer frame. |
| `--message-timeout` | 120 | Deadline for a frame after its first byte, and for a queued message's actual write. |
| `--sync-response-timeout` | 300 | Deadline for a requested headers message or block body, starting after its request is flushed. |
| `--tor-bootstrap-timeout` | 180 | Deadline for one attempt to bootstrap Tor directory connectivity. |
| `--tor-service-startup-timeout` | 1200 | Time allowed for the anonymous onion service to publish and become reachable. |
| `--tor-circuit-request-timeout` | 60 | Arti circuit acquisition deadline. |
| `--tor-circuit-request-attempts` | 8 | Maximum circuit construction attempts per Arti request. |
| `--tor-intro-rendezvous-attempts` | 3 | Maximum introduction/rendezvous attempts per onion connection. |
| `--tor-max-circuit-dirtiness` | 600 | Maximum age for reusing a used circuit without strong isolation for new streams. |
| `--tor-disused-circuit-timeout` | 3600 | Retention of disused circuits with strong stream isolation. |
| `--retry-initial` | 60 | Minimum application connection retry delay; also Arti bootstrap retry initial delay. |
| `--retry-max` | 3600 | Maximum application retry delay, including jitter. |

All durations and attempt counts must be positive, and the retry maximum must
be at least the initial delay. Retry delay grows exponentially and is jittered
within a bounded range even at the cap. Jitter changes retry timing, not the
configured peer count. Active streams are not rotated when a circuit becomes
ineligible for new streams; long-lived duplex connections retain their circuit.

Protocol version 4 completes the application handshake on receipt of a valid
Version. The listener queues its Version reply and first application messages
in the same flight. There is no Verack wait, user-agent string, per-node protocol
version, or additional application authentication exchange. Version still checks
the network genesis, shared protocol number and anti-self nonce.

An onion connection authenticates its destination service. It does **not**
authenticate an incoming caller's advertised onion address. An inbound claim
must not evict an authenticated outbound connection or grant verified-address
status by itself. This limitation also applies to deterministic duplicate
connection handling; address comparison alone cannot authenticate inbound claims.

When opposite-direction connections overlap during discovery or startup, a
`ConnectionLink` control frame binds the reverse stream using a fresh nonce
sent only on the authenticated outbound connection. The nonce is echoed over
the other authenticated direction; a bare inbound address claim cannot supply
it. After binding, address ordering keeps the smaller onion as dialer and the
larger endpoint retains the corresponding inbound stream. Normal application
handshake readiness does not wait for this optional duplicate-collapse message.
The two circuits can overlap while they are discovered and bound; the address
alone cannot safely eliminate that bootstrap overlap.

The Arti setters used by the implementation were checked against the vendored
source and compiled: `stream_timeouts().connect_timeout(...)`,
`download_schedule().retry_bootstrap().initial_delay(...)`, and
`circuit_timing()` setters `request_timeout`, `request_max_retries`,
`hs_intro_rend_attempts`, `max_dirtiness`, and `disused_circuit_timeout`.
The existing service launcher uses `launch_onion_service` and obtains its identity
from `RunningOnionService::onion_address`.

Arti's preemptive-circuit configuration predicts exit ports; the integration has
no verified public API for prewarming a circuit to a particular onion peer.
No such API is invented here. Pool maintenance runs in the background and
refills a slot after a failed or closed connection with configured backoff. It
does not predict failure or establish a replacement before a live connection
dies: doing so would temporarily require another rendezvous, and the current
Arti integration exposes no targeted onion prewarming API. The vendored
onion-service configuration has no implemented single-onion option. Guard/vanguard selection and directory sources
retain Arti's defaults except for full vanguards and the settings listed above.

Tests use explicit memory streams and confirm deadline separation, retry bounds,
handshake behavior and CLI parsing. They do not establish live Tor latency or
throughput. The repository's built-in seed list is empty; deployments must supply
real onion peers through `--seed`, `--addnode`, or `--connect` until release seeds
are assigned.
