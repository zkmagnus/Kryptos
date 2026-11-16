# Seed derivation compatibility and CI vector correction

Status: compatibility review and test-only correction. The proposal was written
before changing the tests. Production seed/key derivation is preserved.

## Problem and evidence

`wallet::seed::tests::derivation_is_pinned_and_accounts_differ` expected
`aeee2840de33f371c576fdde22e552725f6e7002c642a64cbfbaa71679dddaf3`, but the
implementation returns
`88cffd3a1ae06fdcc3096cfdd5d488961565de3fbc9d981117ba84edecd4863a`.

The inconsistent assertion and the production derivation both entered the first
repository commit, `39d1956ecc881150596ad0bd1981e189c8cb477e`. The derivation
domains `IP32Master______` and `ExpandSeed______` also have that provenance.
`git diff 39d1956 851546b -- crates/wallet/src/seed.rs crates/crypto/src/rip1.rs`
is empty. The earlier clean-baseline test failure at `851546b` is recorded in
[the public fee notes](public-transaction-fees.md). Thus this failure is not
introduced by ML-KEM address changes or the CI configuration.

An independent implementation using Python's standard-library `hashlib`
PBKDF2-HMAC-SHA512 and BLAKE2b reproduces the current production result, including
the intermediate derivation stages and account 1. It neither imports Rust code
nor reads values from Rust test output. Before checking the Rhombus vectors, it
checks the standard BIP39 all-zero 256-bit entropy vector with passphrase
`TREZOR`, whose seed starts `bda85446c6841370`. That reference is published in
[Trezor's BIP39 vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json)
and included in the locked `bip39 2.2.2` crate's test vectors.

The available history does not identify how `aeee2840...` was obtained. No
alternative historical derivation is established by that assertion alone.
Changing production domains or key derivation to chase this value would risk
orphaning existing wallets, so this correction changes only test expectations
after independent verification. It does not invent a legacy recovery scheme.

## Derivation being preserved

For the public test phrase consisting of 23 `abandon` words followed by `art`:

1. Derive 64 bytes with PBKDF2-HMAC-SHA512, 2,048 rounds, NFKD mnemonic as
   password and `mnemonic` plus NFKD BIP39 passphrase as salt. Rhombus uses an
   empty passphrase; the `TREZOR` passphrase is only a BIP39 reference check.
2. Compute `I = BLAKE2b-512(seed, personalization="IP32Master______")`.
   Its first 32 bytes are the spending key and the last 32 bytes the chain code.
3. For each hardened index `i`, compute
   `I_child = BLAKE2b-512(c_parent || 0x81 || sk_parent || LE32(i | 0x80000000),
   personalization="ExpandSeed______")`, with the same 32/32 split.
4. Follow `m / 32' / 1' / account'`. This is Rhombus's ZIP32-style hierarchy,
   not a claim of byte-compatible Zcash ZIP32 derivation.

| Stage | Spending-key bytes for the public test vector |
|---|---|
| Master | `939edc84b8082c372f6946ba2ba426a3643f557279559b3948b630c6c38d26b3` |
| `m/32'` | `6c7f416029f7af9a825c7708d0104dbcba1bd90389672eb25fbfa12b82a6a48f` |
| `m/32'/1'` | `998868c0baa59b676dde0d0dfbdb0d39663d3ec9a7ea51c96625fceef11d2f75` |
| Account 0 | `88cffd3a1ae06fdcc3096cfdd5d488961565de3fbc9d981117ba84edecd4863a` |
| Account 1 | `7736bcda73926421570caa1d2375dc2d71ddc33c32194be23d78f80658274f84` |

These are public, unusable-for-funds test keys, not user wallet material.

## Change, compatibility, and failure coverage

Replace the inconsistent account-0 assertion with the independently established
vector, pin account 1 as well, and pin the BIP39 seed and intermediate hierarchy
stages. Keep account-range rejection, seed checksum tests, round-trip parsing,
and address encoding checks enabled. The independent script also checks its
fixed reference values rather than merely printing newly generated results.

There are no changes to wallet production code, stored spending keys, seed
phrases, address derivation, consensus, transaction encodings, proof inputs,
fees, issuance, nullifiers, or reorg handling. No network activation, database
migration, or new genesis is required. Existing wallets produced by the reviewed
repository derivation retain their keys. Unpublished external derivations cannot
be inferred from the available history; retain original wallet files when
investigating such cases.

Run the independent calculation and focused Rust regressions with:

```sh
python3 scripts/check_seed_vectors.py
cargo test -p wallet --lib seed::tests --locked --offline
```

The independent script passed, and all four focused seed tests passed locally.
Rustfmt and `git diff --check` also passed. A source comparison confirms the
non-test portion of `wallet/src/seed.rs` and all of `crypto/src/rip1.rs` are
unchanged by this correction.
