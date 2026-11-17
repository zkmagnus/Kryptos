# Mining readiness

An online Rhombus node mines only after its embedded Tor client and onion
service are ready. Tor readiness is a transport condition; it does not prove
that the node is on the current chain.

For a node joining an existing network, mining also requires the configured
number of authenticated maintained onion peers and completion of the initial
header/body synchronization check. Unbound inbound connections do not unlock mining. A peer that advertises a higher tip keeps mining paused until sync is
complete or the peer is abandoned after a stall. An unsuccessful sync does not
count toward the required synced-peer minimum. The default minimum is one
authenticated peer; operators can change it with `--mining-min-peers`. Connections to
multiple virtual ports of the same onion identity count as one peer. This is a
connectivity requirement, not a guarantee that peers belong to independent
operators. An incomplete initial check is retried at most once per minute when
more synced peers are needed, with new peers checked before failed ones.

The first node in an intentionally bootstrapped private network can opt into
`--bootstrap-mining`. This bypasses the outbound-peer count while retaining Tor
readiness. It is an explicit chain-start policy and should not be used by a
node that is meant to join an existing public chain.

Mining pauses immediately when Tor readiness or the required peer/sync state is
lost. Work resumes only after the conditions have remained ready for the
configured stability period (`--mining-ready-secs`). Set that value to zero for
controlled tests; a short positive value avoids repeatedly starting and stopping
work during a transient Tor reconnect. Built-in workers cancel current hashing
work when readiness is lost, and late built-in or pool-submitted blocks are
refused while mining is blocked.

The node reports the specific blocker: Tor unavailable, insufficient
authenticated maintained peers, synchronization incomplete, or waiting for stable
readiness. `--bootstrap-mining` does not bypass a connected peer's known sync
work. Explicit offline embedding remains available for controlled tests.

Readiness does not use block timestamp age as a hard gate. A quiet network may
legitimately have no recent block, and requiring a fresh tip would prevent the
miners from producing the next block. Propagation and stale-block behavior must
be measured from node observations and validation events before changing the
consensus block interval.

The runtime metrics report peer counts, mining readiness, locally found blocks,
and the timing samples used by the propagation report. These samples describe
what a particular node observed; they are not a substitute for measurements from
multiple Tor locations.
