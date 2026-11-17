# Circuit constants and generator domains

The native curve code derives the value commitment generator under
`rhombus:Generator` and diversified bases under `rhombus:DiversifiedBase`.
The circuit's committed value-generator multiplication tables must use that
same generator. SpendAuth and commitment randomness use the RedPallas bases
from `reddsa`; those tables are unchanged by the domain update.

Regenerate all tables into a temporary file using the existing tool:

```sh
FIXED_BASE_TABLES_OUT=/tmp/rhombus-tables.rs cargo test -p circuit --test gen_tables --offline -- --ignored --nocapture
```

Copy the result into `crates/circuit/src/constants/tables.rs`, format it with
rustfmt, and run `cargo test -p circuit --lib --test fixed_bases --test prove`.
The generator searches deterministic window constants; do not edit them by hand.
`fixed_bases` checks every window against the native generator.

After the domain update the verifying-key pin is
`795317231dea0ea83c28af9ee83f2137e293d6b6ffe204321dcb2ed56d763ad4`.
The deterministic proof and transaction vectors also change because their
witness points, commitments, and proof transcript depend on these domains.
Update their pins only alongside verified generator/table changes, retaining
proof verification and invalid-input rejection checks.

This change alters cryptographic consensus and generated addresses. Existing
proofs, commitments, and addresses made under the previous domains are not
converted by table regeneration. The chain rules digest includes the verifying
key and refuses databases created under incompatible rules; this is a launch
parameter change, not a scheduled migration of existing funds.
