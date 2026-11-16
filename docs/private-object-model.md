# Rhombus Generic Private Object Model

Status: architecture proposal; it is not an active consensus rule or
implementation. This document defines targets an implementation must satisfy.
Adding a new struct alone does not meet those targets.

## Product Decisions

The decisions agreed with the user are:

1. Objects can be consumed and replaced. Their identity does not have to persist
   across transactions.
2. Objects have individual types, state, and operation rules. RHOM coins are one
   object type; the system must support non-coin types.
3. Owners, state contents, object types, and operation kinds are hidden from
   network observers. Choosing a public verifier based on type does not satisfy
   this requirement.

This privacy is against public observers. A recipient needs to learn an object’s
state and type to use it. Transaction participants may also learn the parts of
the transaction they agree on. The built-in coinbase/mint context is a public
exception because of its block position and issuance rules; user transaction
operation choices remain private.

## Difference From the Current Implementation

The current implementation is a shielded note/UTXO model. `protocol::Coin`
contains a recipient, value, rho, and randomness. The builder pairs spends with
outputs, while the action circuit proves membership, ownership, nullifiers,
output commitments, and value balance. There is no type-program authorization
or generic state-operation validation.

| Area | Current implementation | Target |
| --- | --- | --- |
| Private unit | Coin with fixed value fields | Typed object with schema-defined state |
| Rules | Spend and create with balance | Operations authorized by the type program |
| Coin | The only state form | `Coin<RHOM>` as a built-in type |
| Non-coin types | Unsupported | Independent state and rules |
| Proof | Fixed transfer-action relation | Execution of object rules and their effects |
| Kernel | Verify transfers and apply outputs | Verify object transitions and apply effects atomically |
| Wallet | Unspent coins and amounts | Object inventory, schemas, authorization, and operations |

The commitment tree and nullifier set can still serve as public storage and
prevent reuse. What changes is the semantics enforced by the proof and kernel.
There is no claim that commitment/nullifier primitives alone turn a system into
either a note or object model.

## Object Shape

Conceptual private witness:

```text
PrivateObject {
    type_id,
    schema_version,
    owner,
    state,
    uniqueness_nonce,
    commitment_randomness,
}
```

`type_id` identifies a type definition and its authorized immutable rules.
`schema_version` identifies the state encoding version; it is not an object
identity that must persist. `state` is a canonical encoding with a bounded
length. Changing the schema, ownership, or type must change the commitment.

Each output object receives a new uniqueness nonce and fresh randomness. Its
commitment binds the protocol domain, type/schema, ownership, state length and
contents, and nonce/randomness. There is no universal `amount` field; amount is
state specific to the coin type.

The first phase uses key-based ownership. Shared mutable objects,
object-owned objects, and reads of mutable state without consumption require
separate concurrency and authorization specifications. Read-only public
protocol constants must be bound to consensus context; programs must not read
external sources whose results can differ across nodes.

## Types and Operations

An authorized type definition binds its schema, ABI version, program artifact,
and constructor/operation authority. A type implementation cannot be replaced
behind the same ID. An upgrade creates a new definition and migration operation
explicitly authorized by the old rules.

An operation is more than a name in an RPC. The proof must execute and check the
rules for its inputs, outputs, arguments, and authorization. Examples:

| Type/operation | Rule that must be proven |
| --- | --- |
| `Coin<RHOM>.transfer` | Input owner authorizes; destination object type and value are preserved |
| `Coin<RHOM>.split` | One object becomes several RHOM objects; total value is unchanged |
| `Coin<RHOM>.merge` | All RHOM inputs are authorized; output contains their total value |
| `Record.transfer` | Owner changes; type and payload are preserved |
| `Record.update` | Owner authorizes; new payload satisfies the schema and update rules |
| `Capability.use` | Rights, scope, usage limits, and effects satisfy capability rules |

A type need not provide every operation. Destroy, constructor, split, and merge
are valid only when the type program allows them. Creating a new type does not
grant authority to create objects of another type. For RHOM, the kernel protects
the namespace and issuance authority.

Example transaction; the entire plan is hidden:

```text
inputs:  Record(owner=A, payload=X), Coin<RHOM>(owner=A, amount=F+C)
calls:   Record.transfer(A -> B), native_fee(F)
outputs: Record(owner=B, payload=X), Coin<RHOM>(owner=A, amount=C)
public:  fee=F, spent markers, fresh commitments, padded ciphertexts, proof
```

Fees are separate from object-transfer semantics. A record transfer does not
need an amount; a coin transfer does not silently reduce state that should be
preserved. Fees are paid using RHOM inputs and, when needed, change outputs,
with accounting bound to the same transaction.

## Proofs That Hide Types and Operations

The kernel uses one universal verification relation per consensus version or
protocol-defined resource class. Class selection is not based on type. The proof
must establish that the executed program is registered and valid without
publishing the selected program, type, or opcode.

The type/program registry has a consensus-defined root. The program list may be
public, while the program selected by a transaction remains a private witness.
Program bytes, schemas, constructor/import permissions, and version rules must
be bound to a registry leaf whose membership is proven. An object’s `type_id`
must match that program’s rules.

The witness includes input objects, membership paths, authorization data, output
objects, program and registry paths, arguments, input/output routing between
calls, execution trace, and active/padding flags.

The minimum public statement binds:

- Network/branch, rules version, permitted registry root, and anchor.
- User-transaction or coinbase context as determined by the kernel.
- All spent markers and output commitments in canonical order.
- Ciphertext-envelope digest and resource/padding class.
- Public fee and mint credit computed by the kernel in a coinbase context.
- A hiding commitment to the intent/operation plan, so the signature approves
  more than effects without binding the operation the signer intended.

A deterministic intent hash is insufficient: low-entropy opcodes or types could
be guessed. Every signature must bind the same statement, including the intent
commitment, ciphertext, fee, and network/branch domain.

Two engineering approaches could satisfy this relation: a restricted
interpreter proven in a circuit, or zkVM execution whose output/journal is
verified by the kernel. Recursive verification is also possible, but it must
hide the selected program and bind the same effects. The existing Halo2 adapter
crate only wraps the transfer circuit; it does not provide either capability.
Choose the backend through prototypes and benchmarks, rather than assuming it
exists because an interface was renamed. A zkVM receipt that requires a public
image/program ID also misses this target: it requires a universal interpreter
with private programs or a proof of valid program selection that still hides the
program’s identity.

## Kernel and Proof Invariants

1. Each active input proves an object opening, membership against the anchor,
   valid type/schema, and consumption authorization for its owner.
2. A spent marker is bound to the same object and is stable across attempts to
   consume it again. A caller cannot choose the marker or change it through an
   opcode, proof randomness, schema, or another program.
3. Every active input is consumed exactly once. Duplicate markers are rejected
   in transactions, blocks, the mempool, and the chain. An object cannot be read
   and mutated without following the consumption rules.
4. Every active output is authorized exactly once by a valid program rule.
   Providing a proof for one effect and applying another must fail. Routing
   between operations and cross-type access rules are also proven.
5. Creating an active object must follow a valid constructor. A program cannot
   create RHOM by attaching the RHOM type ID to arbitrary state.
6. Padding uses an active boolean constrained by the circuit. Empty state or a
   zero value may be a real object; neither can automatically bypass
   membership/ownership as zero-valued dummies do in the old model.
7. For RHOM, inputs minus outputs equal the fee in user transactions. Minting
   follows only the subsidy and fee computed by the kernel. All values and sums
   have explicit range and overflow constraints.
8. The kernel applies all effects atomically after proof and state checks
   succeed. Programs cannot write directly to the chain database.
9. Output uniqueness nonces require a construction whose proof binds them to
   their creation context, rather than relying only on an honest builder’s
   randomness. Constructor rules must prevent cloning unique rights such as
   NFTs or capabilities; a fresh commitment alone does not prove uniqueness of
   rights in the payload.

Final commitment/hash/nullifier constructions, byte-to-field mappings, and
signature schemes require detailed cryptographic specifications. The
conceptual equations in this document must not be used directly to implement
new cryptography without analyzing binding, hiding, uniqueness, and receiver
authorization.

## Encoding Privacy and Resources

Type/opcode/schema/program ID fields do not appear in the clear in transactions
or ciphertext headers. Real inputs/outputs, payloads, traces, and proofs are
padded to public resource classes that are not selected exclusively by a
particular type. Ciphertexts must not be testable against a type through visible
plaintext magic bytes. The public format has a universal envelope version.

Wallet retrieval of schemas/programs must not reveal a private `type_id` through
requests to a server. Registries and artifacts must be available locally through
full/padded synchronization or a privacy-preserving retrieval mechanism. This
applies both when a wallet discovers a new object and when it creates a
transaction.

Observers still learn transaction timing, padding size/class, public fees,
coinbase position, and public effects required by consensus. ZK does not remove
statistical correlation or information learned by counterparties. The goal is
not a claim of anonymity against every side channel.

Input/output slot limits, state/ciphertext lengths, call counts, VM steps, trace
memory, proof bytes, verification cost, and registry size must be consensus
rules. Loops and allocations must be bounded. Fees based on resource class or
envelope size may be public; publishing actual gas for each operation could
reveal the trace. Prices and numeric limits should be set after benchmarking
coin and non-coin programs using the same envelope.

## Required Implementation Changes

| Code area | Required change |
| --- | --- |
| `protocol/coin.rs` | Make coin a typed object state specific to RHOM |
| `protocol/action.rs`, `transaction.rs` | Generic transition envelope, intent commitment, effects, and padding |
| `crypto/commitment.rs`, `poseidon.rs` | Typed-state commitments and new domains from the specification |
| `circuit`, `transaction-circuit`, `transaction-proof` | Universal relation, authorized program execution, and effect binding |
| `chain/validate.rs`, `mempool.rs` | Context/registry checks, effects, freshness, fees, and minting |
| `storage` | Atomic object effects, registry versioning, reorg/recovery |
| `wallet` | Generic object inventory, schema decoding, operation planning, discovery |
| `runtime`, `p2p`, explorer | New encoding and object APIs that do not reveal type/opcode |

Wallets may display types and state they successfully decrypt. Public nodes and
explorers must not reveal types or operations hidden by the proof. Using the name
`coin` for the RHOM balance remains accurate; non-coin objects are not forced to
have monetary value.

## Activation and Acceptance

This changes consensus and wire format. Verifying keys, transactions,
ciphertexts, wallet storage, and rules digests need new versions/activation.
Circuits must not be replaced under a rules identity already used by an old
database. Choose a new development network or an activated migration with
explicit balance conversion rules. This decision has not been made, and the
active network has not been changed.

Testable implementation stages:

1. Define the canonical ABI, commitment/nullifier formulas, registry authority,
   resource classes, and universal proof construction.
2. Build proof relations for two distinct types: `Coin<RHOM>` and `Record`. Both
   use the same public envelope/verifier.
3. Prove coin and record operations, including a record transfer combined with
   an RHOM fee. Tests must verify proofs, not only builder output.
4. Connect the kernel/effects/store and generic wallet, then test restart, reorg,
   double consumption, migration, and rejection of old encodings.
5. Negative tests: type substitution, unregistered programs, schema changes,
   false owners, forged minting, opcode changes after signing, dummy-to-real,
   unauthorized outputs, replay, overflow, and effect swapping.
6. Measure proof/scan/verification/memory costs and check for type/opcode leaks
   through bytes, size, dummy patterns, timing, and error messages. Obtain
   protocol and cryptography review before network activation.

Generic objects are implemented only when the node rejects transitions that
violate type rules through proof verification and the kernel. Documentation,
renaming, or typed-object structs that are not part of the consensus path do not
meet this criterion.
