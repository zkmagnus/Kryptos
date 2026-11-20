# Kryptos Merkle commitments

Block v1 keeps three commitments separate because they authenticate different data. The transaction root commits the ordered txid tree. The body root commits the complete canonical transaction bytes, and the header history root commits the branch through the parent.

## Transaction tree

`tx_root` is the ordered binary Merkle tree of transaction IDs. Each leaf binds its transaction index and txid; padding leaves, internal nodes, and the final root use distinct `TX_ROOT` tags. The final root binds the transaction count. A `TxMerklePath` proves only that an effecting-data txid is included. Kryptos txids deliberately omit signatures and action-proof bytes.

## Block-body tree

`body_root` is over `LE32(transaction_count) || transaction_0 || ...`, using each transaction's canonical encoding. The header is excluded, avoiding a circular commitment. Leaves are 64 KiB chunks; each leaf binds its index, actual length, and bytes. Padding, internal nodes, and final root have separate tags. The final root binds body length, chunk count, and chunk size. `Block::check_body_root` validates the full body commitment, while `BodyMerklePath` can authenticate one chunk against a trusted header root. Neither a body root nor a chunk path validates signatures, action proofs, or state transitions.

## Header-history MMR

`history_root` in a v1 header commits to all header hashes before that header. The append-only depth-32 MMR indexes each leaf by block height and binds the ordered peaks, count, and depth in its root. The current header is appended only after its hash is known, so there is no self-reference. `HeaderMerklePath` proves header membership under a supplied history root; it does not prove PoW, DAA, cumulative work, canonical-chain choice, or transaction validity.

The root must still be authenticated by a normally validated descendant header, a configured checkpoint, or another trusted chain context. A Merkle proof alone never makes a peer-provided root authoritative.

## Compatibility and sync

The unified v1 layout includes all roots in serialized headers and PoW input. It changes genesis hashes and is a network reset; older header layouts are not decoded under the same version byte. P2P, snapshot, database, and consensus identifiers are set to 1 in separate namespaces.

Sync completes the header scan first, then downloads complete block bodies into a temporary quarantine bounded to 16 files and 100 MiB. Responses may arrive out of order; authorization selects a body whose parent is already stored. When the quarantine is full, a needed earlier parent can evict a later child for download retry.

One background worker checks transaction/body roots, signatures, and action proofs without reading or mutating chain state. An opaque authorization token binds the exact block, body bytes, network, and rules. The main actor consumes it and applies header, PoW, anchor, nullifier, state-root, and fork-choice checks serially. Downloaded bytes are never accepted as validated state or relayed before this succeeds. Local validation time does not count as a peer download timeout. Temporary downloads are discarded on shutdown; the next start resumes from the committed tip.

The body tree adds chunk-integrity proofs but does not yet add a chunked P2P download protocol. Snapshot bootstrap remains bound to a local checkpoint; old MMR subtrees omitted from a snapshot remain unavailable for historical membership-path serving. This is local verification after download, not a HistoryStep proof or a way to omit consensus validation.
