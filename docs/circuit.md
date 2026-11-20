# Circuit constants and generator domains

The native curve code derives the value commitment generator under
`kryptos:Generator` and diversified bases under `kryptos:DiversifiedBase`.
The circuit's committed value-generator multiplication tables must use that
same generator. SpendAuth and commitment randomness use the RedPallas bases
from `reddsa`; those tables are unchanged by the domain update.

Regenerate all tables into a temporary file using the existing tool:

```sh
FIXED_BASE_TABLES_OUT=/tmp/kryptos-tables.rs cargo test -p circuit --test gen_tables --offline -- --ignored --nocapture
```

Copy the result into `crates/circuit/src/constants/tables.rs`, format it with
rustfmt, and run `cargo test -p circuit --lib --test fixed_bases --test prove`.
The generator searches deterministic window constants; do not edit them by hand.
`fixed_bases` checks every window against the native generator.

After the domain update the verifying-key pin is
`c6c4a8a4fec27ed24f3ad709f2a9a1c4f118ce37efdfdafa98e3195fb00fe4b0`.
The deterministic proof and transaction vectors also change because their
witness points, commitments, and proof transcript depend on these domains.
Update their pins only alongside verified generator/table changes, retaining
proof verification and invalid-input rejection checks.

This change alters cryptographic consensus and generated addresses. Existing
proofs, commitments, and addresses made under the previous domains are not
converted by table regeneration. The chain rules digest includes the verifying
key and refuses databases created under incompatible rules; this is a launch
parameter change, not a scheduled migration of existing funds.

## Mining proof regression (2026-11-20)

A native/circuit generator mismatch was reproduced by
`value_commit_v_tables_match_the_generator`: native value commitments used
`kryptos:Generator`, while the committed value-base windows still described the
previous generator. A prover can emit a proof from this inconsistent witness,
but verification rejects it, including locally mined coinbases.

Regenerating the tables changes only `VALUE_COMMIT_V_Z` and `VALUE_COMMIT_V_U`;
SpendAuth and randomness tables remain unchanged. Proof and transaction vector
pins are updated only after successful verification. The mainnet mining
regression `mainnet_mined_coinbase_proof_is_accepted` uses an easy PoW target
and imports a mined block through normal chain validation.

Rebuild node binaries after this fix. The verifying key and chain rules digest
change; retain existing databases rather than editing their rules metadata to
bypass an incompatibility error.
