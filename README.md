# Rhombus

**RHOMBUS — Randomized Hidden-Output Monetary Blockchain Using Shielded-transfers.**

***EXPERIMENTAL***

## Explorer

The node's JSON-RPC HTTP endpoint serves a small local explorer at `/` (also
`/explorer`). Open the logged JSON-RPC URL in a browser and enter the node token
from `rpc.token`. The HTTP listener is enabled by default; `--rpc-http
127.0.0.1:18443` sets its address explicitly. The explorer looks up blocks by
height or hash and transactions by txid. See [the explorer notes](docs/explorer.md).

Address activity is shielded: public block data does not reveal which address
received a note or its value. Use the wallet with the corresponding viewing
key to scan address activity.
