# RPC resource limits and reorganization recovery

The text control server accepts at most 32 simultaneous sessions. Before
successful authentication, a line is limited to 256 bytes including its newline;
authenticated lines are limited to 32 MiB. Each line read has a 30-second deadline;
response writes and client reply reads allow 120 seconds for onion latency and
large block replies. Oversized, incomplete, or timed-out lines close the session.

A text RPC client retains its embedded Tor instance and authentication token for
its connection. If a read-only request (`status`, `hash`, `block`, `compact`,
`coinbase`, `txstatus`, or `spent`) loses its stream, the client discards any
partial reply, opens a fresh isolated onion stream, authenticates, and retries
that request once. The initial dial/authentication also permits one retry on a
transport failure. Opening a session is bounded by 240 seconds per attempt;
request writes and reply reads each have their own 120-second limit. A bad token,
node error, malformed reply, or explicitly closed session is not replayed.

Submissions and unknown commands are never automatically replayed. If their
connection fails after sending, the error reports that the outcome is unknown;
check the transaction id with `txstatus` before deciding to submit again. Failure
messages distinguish Tor readiness, onion dialing, authentication, request
writing, reply reading, and session closure without echoing tokens or request
arguments. Closing a fully downloaded session is idempotent, including when the
peer has already disconnected. Closing ends that download session before private
wallet scanning; a later command must open a new session. The `send` command
reuses the same embedded Tor instance for download and submission, but opens a
fresh authenticated stream after proof generation. This avoids holding two Arti
instances on the same client state directory.

The embedded transport samples current bootstrap status when an Arti event wakes
it, instead of treating a queued earlier event as a new readiness loss. An onion
rendezvous request listener remains present while any accepted application stream
is alive. The 60-second idle listener expiry applies only after all such streams
have been dropped; circuit tasks, incoming streams, and concurrent handshakes
remain bounded. This avoids closing a reused circuit because its request listener
was retired during a long RPC download. It does not identify the cause of every
`Stream not connected` report; real network failures can still occur.

Deterministic tests cover partial replies, authentication interruption, bounded
read retries, mutation non-replay, and explicit closure. Public Tor coverage is
opt-in: `cargo test -p runtime --test rpc_real_tor -- --ignored --nocapture` checks
status/hash/compact reads, a fresh wallet's balance snapshot download/scan/close,
the already-synchronized light path, recovery after the server's idle timeout,
and a fresh session. On November 16, 2026, this expanded test passed over public
Tor in 112.40 seconds including bootstrap. It used a fresh genesis-only test node
and an empty test wallet, not the reported user's wallet or mining deployment.
The test now keeps its temporary Tor directories alive until runtime shutdown so
background-task teardown can flush state. It is not a throughput or multi-location
propagation benchmark.

The shared node/wallet HTTP RPC server accepts at most 16 simultaneous
connections. Excess connections are closed immediately. Request reads and
response writes each have a 30-second deadline. Authorization is checked after
the headers, before reading the body; an unauthenticated POST receives 401 without
waiting for its declared body. Authorized bodies retain the existing 32 MiB
limit. Proof generation and method dispatch are not cancelled by these I/O
deadlines.

Before a reorganization changes the canonical chain, storage commits the
original tip and fork hashes together in the metadata table. Commitment-tree
frontiers are not pruned while this journal exists. Completing a reorganization
clears the journal before normal pruning resumes.

On startup, after checking the network and rules digest, an unfinished
reorganization is rolled back to the original chain. Recovery also runs before
subsequent imports, covering interrupted operations within the same process.
It reverts to the recorded fork and replays the previously validated original
blocks, rebuilding tree frontiers, transaction indexes, and nullifiers. Recovery
checks the reconstructed commitment roots. Every step is durable, and the
journal is cleared only after the original chain has been restored, so another
interruption can safely restart recovery.

Stored noncanonical blocks are reconsidered when explicitly imported; only
blocks already on the canonical chain immediately return `AlreadyKnown`.
No transaction-validity rule, wire encoding, or consensus digest changes.
Existing databases can be opened without a resync. Use the updated binary to
recover a database with an unfinished journal; older binaries do not implement
this recovery procedure.
