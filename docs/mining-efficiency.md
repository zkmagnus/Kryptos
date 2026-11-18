# Retaining prepared mining work

The built-in miner used to assemble and prove a new coinbase before every batch
of 32 RandomX nonces. An unchanged parent and transaction selection do not need
another proof: the random nonce and current timestamp belong to the block
header, outside the coinbase proof.

Workers now retain their prepared header/body after an unsuccessful batch. A
batch ends after 32 nonces or five seconds, whichever is reached first, checked
between nonces. The worker then fetches the current selected transactions and
updates its header timestamp. It reuses the proof only when the parent header,
difficulty history, commitment frontier, full selected transactions and network
parameters match. Full transaction comparison includes authorization/proof
bytes, which transaction IDs alone do not cover. Changed inputs require a fresh
coinbase and body. Each worker keeps independent prepared work and its own
RandomX VM; workers do not share coinbase proofs.

Stop, best-tip movement, Tor readiness loss, and peer/sync policy revocation are
checked before preparation and before each nonce. A result is also checked
before submission. A blocking proof or RandomX hash already in progress cannot
be interrupted, but its result is discarded if readiness or the parent changed.
Transactions arriving during a batch are considered at the next refresh. Time
spent proving and one in-progress hash can extend that interval.

Pool `getblocktemplate` keeps its five-second response reuse window. On expiry,
it fetches the current selection and reuses an existing coinbase/body only if
all inputs and the payout match; it returns a new template ID with an updated
timestamp. Previous IDs retain the existing ten-minute submission expiry and
64-entry cache bound. Preparation misses are serialized per RPC context, so
simultaneous equivalent requests use one completed proof and return the same
fresh ID. Different payouts also queue behind preparation, bounding concurrent
prover load at the expense of latency for unrelated cache misses. Cached hits
can still proceed independently.

Newly prepared or refreshed pool work is checked against current readiness and
the exact parent hash after preparation, including replacement tips at the same
height. It is rejected if the node lost readiness or moved to a different tip.
Consensus validation, emission, fees, RandomX inputs, target calculation and
accepted block/transaction encodings are unchanged.

## Validation and measurement

The focused regression `prepared_work_reuses_proof_but_rejects_changed_inputs_and_cancels`
compares actual coinbase assembly with 64 unchanged-work refreshes, checks body
identity and input invalidation, cancellation, independent random nonces across
unsuccessful batches and a valid RandomX solution. On an Intel Core i7-8550U,
Rust 1.100.0, optimized test profile (`opt-level = 1`), one run measured **4.298 s**
for assembly/proving and **15.797 us** for 64 in-memory work refreshes. This is a
single local operation-level measurement, not a repeated statistical benchmark
or an end-to-end mining/hash-rate claim. Run the comparison locally with:

```sh
RUSTFLAGS="" CARGO_BUILD_JOBS=2 cargo test -p runtime --lib prepared_work_reuses --locked --offline -- --nocapture
```

The JSON-RPC preparation regression passed for same-height tip replacement and
readiness loss after the template snapshot. A socket-free context test also
passed for concurrent requests sharing the template ID/body and an expired response refresh
retaining that body without another proof. The pool integration test additionally
covers timestamp refresh and block submission through HTTP. Its build succeeded,
but this session could not execute the node fixture because the sandbox denied
loopback binding; an escalation attempt was not executed after automatic review
hit a rate limit. The existing HTTP submission assertions still need a run in an
environment permitting local sockets.

This removes repeated proving from unchanged work; it does not change the cost
of a RandomX hash. End-to-end hash-rate, competing-miner fairness, and public-Tor
throughput require separate measurements.
