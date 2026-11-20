# Wallet backup and restoration

`backupwallet` exports the complete version-1 plaintext wallet JSON under
the `kryptos-wallet-plaintext-backup` format identifier. Earlier development
exports with the old format identifier are not accepted.
`restorewallet` restores that export to a new database for the selected network:

```sh
kryptos backupwallet --network test --wallet wallet.redb --out wallet-backup.json
kryptos restorewallet --network test --backup wallet-backup.json --wallet restored.redb
```

Stop the wallet daemon before exporting, and keep the source database and backup
until restoration has been verified. Synchronize the restored wallet before
spending. Avoid running the original and restored copies concurrently: independent
copies share spending keys and address counters but cannot coordinate new address
allocation or pending payments.

The export contains the spending key and its fingerprint, network genesis,
address scheme and allocation counters, labels, active receiving address and
automatic receive-rotation preference, owned coins and spent state, scanned block
history, witness tree/checkpoints, and send operations. Import preserves these
records, including address reservations from failed or interrupted transaction
construction. It rebuilds the derived coin-nullifier index. JSON restoration
therefore needs no separately supplied address range. Version-2 exports made
before this reset are rejected by their old format identifier. Seed-phrase
restoration remains a separate operation with its documented
`--restore-through` requirement; this feature does not change address derivation.

Both commands create a private temporary file alongside the destination, finish
writing and syncing it, and publish it without overwriting an existing path.
Failed validation removes the temporary file and leaves the destination absent.
The destination must support same-filesystem no-clobber publication. Files are
owner-readable/writable on Unix; other platforms use their filesystem ACLs.
Unexpected process termination before publication can leave a private staging
file, which should be handled as a wallet secret. The implementation does not
claim power-loss durability of the parent directory entry on every filesystem.

Import rejects unsupported versions, unknown JSON fields, duplicate rows,
malformed encodings, a mismatched network, incomplete allocation metadata,
inconsistent key fingerprints, invalid coin ownership/nullifiers, coin heights
that disagree with recorded block positions, invalid unspent witnesses,
inconsistent scan/checkpoint records, and inconsistent operation IDs.
Retained checkpoints must form a contiguous suffix through the scanned tip;
their tree positions must match the next block's recorded starting position (or
the final tree size at the tip). Recorded removed marks must identify a coin
spent at that checkpoint. A valid suffix can be shorter after rollback, since
older pruned checkpoints are not recreated. These checks establish local
consistency, not that the retained suffix begins at an independently known height.

Transaction IDs in submitted or confirmed status must match the active saved
transaction; confirmed heights must belong to the scanned history. Restore reconstructs
coin reservations for recorded operations from the nullifiers of every retained
transaction attempt and the restored coin records. This replaces stale tree
positions left by reorganizations without forgetting earlier transaction bytes
or changing their status. An unrecorded operation has no transaction nullifiers
to reconstruct from, so its local reservations are preserved (within the tree's
position range) and still require the normal daemon reconciliation procedure.
Version 1 is supported. The backup is trusted local state: structural checks do
not prove its provenance or independently validate its block history against a
node. Use only your own trusted backup and protect it against replacement or
editing.

Neither JSON exports nor wallet databases encrypt secrets. Anyone with read
access can recover the spending key. Store copies offline in protected storage.
This compatibility utility does not implement password encryption, a new seed
recovery design, or a new backup format. A portable encrypted backup and recovery
without external address metadata require a separate design and review.

The focused tests exercise a wallet with received and spent coins, surviving
witnesses, pending operations and address reservations; spending after import
checks the rebuilt nullifier index. They also cover empty wallets and rejection of legacy address metadata, wrong networks, malformed state, existing files/symlinks and staging
cleanup. Corrupt-checkpoint and contradictory operation-status regressions are
paired with successful restoration of a pruned checkpoint suffix after rollback
and a pending operation retaining older attempts and stale position metadata.
Coin-height regressions cover spent and unspent records and verify rollback
after a valid restore. Legacy coins with diversifier indices beyond the local
`u64` address allocator also round-trip with their witnesses and spent state.
Operation-metadata fixtures use structurally encoded dummy proofs; these tests
do not claim to verify transaction authorization. These are generated fixtures,
never user wallet data.
