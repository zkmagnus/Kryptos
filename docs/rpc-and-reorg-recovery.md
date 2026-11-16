# RPC resource limits and reorganization recovery

The text control server accepts at most 32 simultaneous sessions. Before
successful authentication, a line is limited to 256 bytes including its newline;
authenticated lines are limited to 32 MiB. Each line read and response write has
a 30-second deadline. Oversized, incomplete, or timed-out lines close the session.

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
