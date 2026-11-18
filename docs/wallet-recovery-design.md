# Wallet recovery design

Status: proposal, not an implemented address/encryption protocol or a public
network activation. This design describes a replacement user experience without
requiring it to mirror the existing JSON table dump. The compatibility JSON
restore utility and this future recovery format are separate deliverables.

## User contract

A fresh wallet should have one offline recovery phrase (24 BIP39 words, 256 bits
of entropy) for the default account, with an explicit wallet format/derivation
version and network identified by recovery software. A local unlock password
protects the installed wallet; changing it must not change the wallet's keys or
addresses. A password is not an extra BIP39 seed passphrase by default: an
unrecorded extra seed passphrase would change the recovered account.

There are two recovery paths:

- The phrase recovers spending/viewing keys and, once the protocol supports
  complete payment discovery, confirmed spendable state by scanning validated
  chain data. It does not recover local labels, unbroadcast transactions,
  preferences, or unpublished address reservations. Arbitrary extra accounts
  also need a defined discovery contract; start with one default account.
- A portable authenticated encrypted backup recovers keys plus account/version,
  network genesis, address allocations, labels, operations and scan hints. It
  avoids having to guess those local facts. Cached chain state remains
  reconstructible and must be reconciled with a validated chain before spending.

The interface must not report an apparently empty wallet as a successful full
recovery when payment discovery is incomplete. Show scan progress, the validated
height/hash, and the scope being recovered. An optional wallet birthday improves
speed but is never necessary for correctness: missing or suspect birthday data
falls back to genesis. A complete restored backup must not silently rewind its
address allocation counter or discard pending operation reconciliation.

## Portable backup format

Use a versioned logical record format, not redb internals as the long-term
interchange contract. Include an authenticated schema version, network genesis,
key derivation scheme, account index, required recovery metadata, and optional
portable labels/operations. Internal database indexes and witness caches can be
rebuilt; a snapshot extension may speed recovery but is not trusted consensus
state.

Encrypt the whole payload with a reviewed AEAD such as XChaCha20-Poly1305 and a
fresh random nonce. Derive the backup key with Argon2id from a backup password,
using a fresh salt. Authenticate the envelope/header as associated data and
apply explicit size and KDF resource limits before expensive parsing/derivation.
Benchmark the KDF on supported devices before fixing minimum/default parameters;
never accept unbounded attacker-selected memory/iteration costs. Wrong password,
authentication failure, unknown schema/network and corrupt files must fail
without publishing a partial wallet. Cryptographic primitives should come from
maintained libraries, not custom encryption.

Backup creation uses a private temporary file, durable write and no-overwrite
publication. Restore likewise stages privately, validates completely and only
then publishes to a new destination. A successful backup must be tested by a
restore/check procedure that compares wallet identity and recoverable state.
Document stale backup behavior: chain scanning can recover later confirmed
payments only when discovery covers them; local state created after the backup
is not magically present in it. Encryption provides confidentiality/integrity,
not protection against replaying an old but valid backup.

## The current discovery obstacle

Rhombus currently derives a different ML-KEM key for each address. The scanner
tries every configured address key against every output. A phrase determines
keys but not how many address indices were previously reserved. The existing
0..4095 bound makes a full-range recovery finite, but not fast: cost grows as
address keys multiplied by chain outputs. Scanning all 4096 indices could remove
the user's range entry for current-format balances, but it reserves/exhausts the
current address space and may be impractical on a long chain. It is not the
recommended default design and must never be marketed as a scalable fix.

A finite gap limit also cannot guarantee complete recovery of arbitrary unpaid
address reservations. Publishing the address index or a stable wallet identifier
in outputs to make lookup easy would expose linkage and is not an acceptable
implicit change to the current privacy model.

For efficient phrase-only recovery with unlimited address issuance, design an
incoming scan mechanism whose cost is proportional to outputs, independent of
the number of issued addresses. A diversified elliptic-curve discovery envelope
could let one private viewing key find an encrypted diversifier/routing record,
then derive the separate ML-KEM key needed for the payload. This is a candidate
architecture, not a construction ready to implement. A classical-only routing
layer could expose payment/address linkage to a quantum adversary even while
ML-KEM still protects coin contents. Binding, recipient correctness, malformed
outputs, timing leakage, quantum threat model, and privacy claims need explicit
cryptographic analysis. Reusing one visible ML-KEM public key for all addresses
would also restore easy scanability but would link shared addresses.

A fully post-quantum, unlinkable, efficiently discoverable diversified address
scheme is a separate cryptographic research/design requirement; standard
ML-KEM alone does not provide it. Choose and review the privacy contract before
changing address/ciphertext formats or proofs. New and old address versions need
explicit separation and a migration/activation proposal under CONTRIBUTING.md.

## Recommended implementation order

1. Complete and test the current backup restore utility so existing wallets have
   a recovery path. This utility remains explicitly plaintext and versioned.
2. Add the logical authenticated encrypted backup format and restore rehearsal,
   with no dependency on raw database table layout. Include all address/account
   metadata automatically; support import of existing backups separately.
3. Prototype scan discovery with measured recovery time and a documented privacy
   model. Only after independent protocol/cryptography review should the new
   address version make phrase-only complete recovery the default contract.

Do not claim phase 1 implements encrypted backup or that phase 2 alone solves
phrase-only payment discovery. Acceptance tests include damaged/truncated backup,
wrong password/network/version, interrupted restore, no-clobber publication,
address reservations beyond the last used address, incoming/outgoing payments,
change, spent coins, reorganization, stale backup, and local metadata recovery.
