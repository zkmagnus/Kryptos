# Rhombus Explorer

The node serves a local browser explorer from its JSON-RPC HTTP listener:

- `GET /` or `GET /explorer` serves the explorer page.
- Block search accepts a block height or block hash.
- Transaction search accepts a transaction id and displays public transaction
  fields and its confirmation status.
- The same page displays the current mempool and node metrics, refreshed every
  15 seconds while connected. These snapshots use authenticated JSON-RPC calls,
  so no separate Prometheus listener is needed for the explorer.
- The page connects to the same JSON-RPC endpoint and requires the node's
  `rpc.token`. It keeps the token in page memory only; it does not persist it in
  browser storage. The endpoint is fixed to the origin serving the page;
  cross-origin requests and redirects are rejected. A `connect-src 'self'`
  content-security policy provides an additional browser-side restriction.

The JSON-RPC HTTP listener is enabled by default. Open the logged `json-rpc`
URL in a browser; to set it explicitly, use `--rpc-http 127.0.0.1:18443`.
The listener accepts only `127.0.0.1` binds. It may also be reached through the
node's Tor HTTP service mapping. The token grants access to node RPC methods,
including methods beyond read-only explorer queries.

`getrawmempool`, `getmempoolinfo`, and `getmetrics` supply the pending
transaction ids, mempool capacity, and node snapshot shown by the page.

## Address lookups

Rhombus transfer outputs are shielded. Public block data exposes commitments,
nullifiers, and encrypted note payloads, but does not expose the recipient
address or note value. The explorer therefore cannot build a public address
activity index from chain data alone. To see activity for an address, scan with
the wallet holding the corresponding viewing key. Address lookup in the
explorer explains this limitation instead of presenting incomplete results as
an empty history.
