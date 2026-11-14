# Rhombus Explorer

The node serves a local browser explorer from its JSON-RPC HTTP listener:

- `GET /` or `GET /explorer` serves the explorer page.
- Block search accepts a block height or block hash.
- Transaction search accepts a transaction id and displays public transaction
  fields and its confirmation status.
- The page connects to the same JSON-RPC endpoint and requires the node's
  `rpc.token`. It keeps the token in page memory only; it does not persist it in
  browser storage.

The JSON-RPC HTTP listener is enabled by default. Open the logged `json-rpc`
URL in a browser; to set it explicitly, use `--rpc-http 127.0.0.1:18443`.
By default, the listener is bound to localhost. Keep it on a trusted interface
because the token grants access to node RPC methods, including methods beyond
read-only explorer queries.

## Address lookups

Rhombus transfer outputs are shielded. Public block data exposes commitments,
nullifiers, and encrypted note payloads, but does not expose the recipient
address or note value. The explorer therefore cannot build a public address
activity index from chain data alone. To see activity for an address, scan with
the wallet holding the corresponding viewing key. Address lookup in the
explorer explains this limitation instead of presenting incomplete results as
an empty history.
