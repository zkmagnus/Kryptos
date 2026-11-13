# Rhombus

**RHOMBUS — Randomized Hidden-Output Monetary Blockchain Using Shielded-transfers.**

Rhombus is a shielded-only privacy cryptocurrency written in Rust. Its ticker
is `Rhombus`; payment addresses use an unprefixed, checksummed, unpadded
Base58Check encoding of the diversifier and transmission key. Transactions
transfer private coins and are authorized with zero-knowledge proofs built on
Halo2.
There are no transparent addresses.

The current transaction migration selects wire version 3 with one explicit
Transfer opcode, private fees, and a block-wide value binding signature, with
a new genesis for each network. The shielded action proof remains envelope
V2. Fee openings travel as relay metadata; transaction and block encodings do not
publish fee or reward amounts. This is a consensus-breaking development
change: old chain databases and legacy wire histories are incompatible. See
[SYSTEM-CALL-SPEC.md](SYSTEM-CALL-SPEC.md) and [PRIVATE-FEES-DESIGN.md](PRIVATE-FEES-DESIGN.md)
for the ABI and migration status.

Blocks use RandomX proof of work. Nodes run RandomX in light mode and need
about 256 MiB of cache memory for each network key used by the process. The
current mainnet and testnet keys are fixed consensus parameters.

Mainnet and testnet have separate chains and separate Rhombus balances. Addresses
have no visible network prefix, but their checksum is bound to the network and
wallets reject an address from the other network. A payment on testnet is not
a mainnet payment.

The `rhombus` command runs a node, mines blocks, syncs the chain and relays
transactions over encrypted peer connections using Dandelion++. The wallet
can scan balances and send payments. A separate test network is available for
development. Blocks pay 12.5 Rhombus per block initially, then transition to
the 0.125 Rhombus tail after the first million-block emission interval.
Rhombus is experimental
and has not had an independent security audit; see [SECURITY.md](SECURITY.md)
for the review scope and vulnerability reporting guidance.

## License

Rhombus is licensed under the GNU General Public License, version 3 or (at
your option) any later version. See [LICENSE](LICENSE) for the full text.

## Development docs

- [SystemCall ABI draft](SYSTEM-CALL-SPEC.md)
- [SystemCall-based transfer roadmap](SYSTEM-CALL-ROADMAP.md)
- [Bridged stable asset and governance roadmap](STABLECOIN-GOVERNANCE-ROADMAP.md)
- [Development skills and project context](skills.md)
- [Contribution and review guide](CONTRIBUTING.md)

## Build and run

Build the workspace with Rust 1.85 or later:

```sh
cargo build --release
```

Start a mainnet node:

```sh
cargo run --release -p runtime -- run
```

For a development node, select the test network:

```sh
cargo run --release -p runtime -- run --network test
```

### Mine blocks

Create a wallet for the network you want to mine on. This prints its address
and a recovery phrase; save the phrase securely. Wallet files are plaintext
databases with no wallet passphrase, so protect the file and its backups:

```sh
cargo run --release -p runtime -- create --wallet ./wallet-test.dat --network test
```

Start a testnet node and mine rewards to that wallet address. Replace
`<ADDRESS>` with the address printed by `create`:

```sh
cargo run --release -p runtime -- run --network test --mine '<ADDRESS>' --mining-threads 4
```

For mainnet, create a mainnet wallet and use its address with
`run --network main --mine '<ADDRESS>'`. Keep the wallet and node on the same
network; the address text itself does not identify the network. Rhombus has no
built-in seed peers on either network. To connect to peers, pass
`--seed <HOST:PORT>` or `--connect <HOST:PORT>`. Mining can run without peers.

Use `rhombus --help` and `rhombus <command> --help` to see available node and
wallet commands. The node creates a local RPC token in its data directory on
first run; wallet commands use that token to connect to the node.

### Scan a local chain

`rhomscan` scans blocks from the local chain database into an existing wallet
without connecting to the node RPC. Defaults use the current working directory's
`rhombus-data/<network>/` directory:

```sh
cargo run --release -p runtime --bin rhomscan -- --network test
```

Use `--light` to scan compact actions without recovering memos, `--verbose` to
print found coins, or `--chain` and `--wallet` to select database files.
The scanner follows the local chain tip and rolls the wallet back when it sees
a reorganization.

### Batch transfers

`batchtransfer` sends several recipients in one transaction and one proof.
Amounts are in raw units, and each `--payment` is `ADDRESS=RAW_AMOUNT`.
Wallet send commands default to a fee of one raw unit per encoded
transaction byte; pass `--fee` to set an explicit fee in raw units. Fee
amounts travel with encrypted node-to-node relay metadata and are omitted from
transaction and block encodings. A block-wide binding signature proves that
the coinbase value is limited to the subsidy plus the aggregate fees:

```sh
cargo run --release -p runtime -- batchtransfer --network test \
  --wallet ./wallet-test.dat \
  --payment '<ADDRESS_1>=250000' \
  --payment '<ADDRESS_2>=400000'
```

Transactions carry the Transfer opcode and dispatch into the existing shielded
action proof and balance checks. The opcode has no public payload, so the
recipient and amount remain private. Wallet RPC clients can also use `sendmany`.
