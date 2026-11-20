# Public deterministic transaction fees

## Status

The chain is assumed to be reset for this change. Existing databases and
historical transaction compatibility are out of scope.

## Motivation

The previous design kept a transaction's fee and commitment blinding in
out-of-band metadata. Transactions did not carry that information, so peers,
wallets, mempool admission, and block construction had to preserve it
separately.

The new design makes the fee public and deterministic from the encoded size:

```text
fee = FEE_PER_BYTE * encoded_transaction_length
FEE_PER_BYTE = 1 oriul per byte
```

This lets every node derive the same fee from the transaction itself. Since
action count can reveal information about transaction shape, the protocol
already pads to an allowed action class whose minimum is two actions.

## Native transfers and encoding

- Shielded transfers are validated and applied directly by chain consensus.
  The `systemcall` dispatcher and `program-vm` opcode crate were removed.
- The reset chain uses transaction format version `1`. The former transfer opcode and
  SystemCall entrypoint fields are gone; a native transaction kind distinguishes
  transfers from coinbase records.
- The transaction header includes the fee as an unsigned 64-bit little-endian
  field after the anchor and before the action count.
- Fee is part of effecting data, so it affects both `txid` and the sighash.
  Altering the fee after signing therefore invalidates the signatures.
- Stateless transfer validation calls `Transaction::check_fee()`, which
  compares the declared fee with the exact canonical transaction encoding
  length. Coinbase transactions must declare zero fee.
- Each transfer binding signature proves its own net value equals its fee.
  Coinbase has a binding signature against the negative mint computed as
  subsidy plus all included transfer fees. The validator needs no aggregate
  blinding from transaction senders.
- Blocks no longer carry an aggregate binding signature. Their format has
  changed accordingly.
- Fee-opening payloads were removed from transaction relay, mempool state,
  command-line submission, RPC submission, and wallet operation records.
- Minimum action padding remains provided by the existing action classes
  `[2, 4, 8, 16]`.

## Emission schedule

- The first non-genesis block pays 25 BUS (`2,500,000,000` raw units).
- Blocks 1 through 525,600 inclusive pay the initial reward. At a nominal
  120-second block interval and 365 days per year, that is 720 blocks per day,
  262,800 per year, and two nominal years.
- The initial-reward issuance is 13,140,000 BUS (`1,314,000,000,000,000` raw
  units). The permanent tail begins at height 525,601 and pays 0.25 BUS
  (`25,000,000` raw units) per block.
- Genesis pays no subsidy. Transfer fees are added to the coinbase mint and
  do not increase scheduled issuance.

## Files changed

- `crates/protocol/src/fee.rs`: deterministic fee calculation, block mint,
  and overflow-checked fee summation.
- `crates/protocol/src/transaction.rs` and `consensus.rs`: the native transaction format,
  encoded fee field, and fee inclusion in effecting data after removing the
  opcode and SystemCall target.
- `crates/protocol/src/builder.rs` and `validate.rs`: fee-aware transaction
  construction and stateless validation/signature setup.
- `crates/crypto/src/signature.rs` and `commitment.rs`: binding-key equation
  coverage for the public transaction balance.
- `crates/chain/src/validate.rs` and `runtime/src/miner.rs`: per-transaction
  binding verification and shared fee-based mint accounting.
- `crates/protocol/src/block.rs`, `crates/p2p`, and runtime block-template
  paths: removal of aggregate block binding signatures.
- `crates/p2p`, `runtime`, and `wallet`: removal of fee-opening relay and
  submission plumbing.
- `crates/chain/src/validate.rs` and `mempool.rs`: native transaction checks
  and direct action effects, with no SystemCall dispatcher.
- `crates/protocol/src/consensus.rs`: 25 BUS initial subsidy through height
  525,600 and 0.25 BUS tail from height 525,601.
- Chain tests were adjusted to treat fees as public transaction fields.

Changing `FEE_PER_BYTE` changes consensus and requires a coordinated protocol
upgrade. Transaction bytes and block bytes changed; chain reset is assumed.

## Verification performed

- `cargo check --workspace` passes after replacing the dispatcher and VM
  opcode crates with native chain transaction validation.
- `cargo test --workspace --no-run` compiled all active workspace test targets
  before the version reset.
- `cargo test -p protocol --lib`: 104 passed.
- `cargo test -p chain --test chain --test mempool`: 27 passed.
- Runtime RPC, sync, and wallet daemon integration tests pass (7 total).
- Runtime mining integration tests pass (2/2), including the new subsidy RPC
  value.
- The previous fee-only workspace audit had all tests pass except
  `wallet::seed::tests::derivation_is_pinned_and_accounts_differ`.
- That remaining test expects spending key
  `aeee2840...79dddaf3`, while the unchanged RIP1 derivation code returns
  `88cffd3a...ecd4863a`. The mismatch is present in the committed baseline
  (`seed.rs` and `rip1.rs` were not changed here); the expected vector needs
  a separate derivation compatibility review.
- Chain integration tests pass (20/20), including fee-bearing transfers,
  tampered fee rejection, coinbase mint checks, and consensus branch
  activation. Mempool integration tests pass (7/7).
- Protocol unit tests pass (104/104); circuit tests pass (30/30), crypto
  tests pass (99/99), and runtime unit/integration tests pass, including the
  RPC, sync, miner, mining, discovery, and wallet daemon targets.
- Existing ignored tests remain ignored: proof-size measurement, fixed-base
  table regeneration, and storage nullifier lookup measurement.
- `cargo fmt --all` completed successfully for the current changes.

