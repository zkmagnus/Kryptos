# ML-KEM coin encryption proposal

Status: implementation draft; not activated on a public network.

## Motivation

Add post-quantum key establishment for encrypted coin payloads while keeping
the current spend authorization, diversified Pallas transmission key, coin
commitment, nullifier, and proof circuit unchanged. This is a hybrid protocol:
ML-KEM protects coin encryption key establishment; it does not make the
shielded pool or spend authorization post-quantum.

## Rules and encoding

- Derive an ML-KEM-768 receiver key pair deterministically from the full viewing
  key material and the address diversifier. The existing `ak`, `nk`, `rivk`,
  `ivk`, `pk_d`, and diversifier derivations remain unchanged.
- Each new payment address carries its own ML-KEM encapsulation key. Legacy
  addresses used one shared key for all diversifiers of a full viewing key;
  those existing addresses remain linkable. The legacy derivation is retained
  for receiving old payments. See the
  [diversified-key proposal](diversified-ml-kem-addresses.md) for derivation,
  wallet migration, scanning bounds and seed recovery.
- Each encrypted coin carries a fixed-size ML-KEM-768 ciphertext. The sender
  derives the coin AEAD key from the KEM shared secret, ciphertext, and coin
  commitment. ChaCha20-Poly1305 and the current plaintext remain in use.
- The action carries only the ML-KEM ciphertext and recipient-encrypted coin
  payload. There is no generic sender recovery key or outgoing ciphertext;
  wallets still detect their own change through normal incoming scanning, while
  payment details to other addresses must be retained locally at send time.
- Compact actions carry the KEM ciphertext plus the existing encrypted-coin
  lead. Light-wallet scans decapsulate, decrypt the lead, and confirm the
  existing coin commitment.
- The encrypted coin, transaction, block, and action proof envelope each use
  version `1` on the reset chain. Updated wallets retain support for legacy
  addresses.

## Compatibility and activation

ML-KEM changes address and action bytes and compact blocks; removing the
outgoing ciphertext further changes full action and transaction bytes, IDs,
and size-based fees. The reset starts at consensus revision `1` with a new
genesis for each network and a new rules digest. A node rejects earlier chain
databases and peers announcing an earlier genesis hash. Use a fresh data
directory and recreate the wallet from its seed if you want to keep the same
keys. This does not restore balances from the earlier chain. Compact action
encoding is unchanged by removing the outgoing ciphertext.

The later change from shared to diversified ML-KEM address keys does not alter
this encryption format or transaction validity. Senders already encrypt to the
key supplied in an address. It requires an updated receiving wallet and an
explicit address range for seed-only recovery, not a chain reset. Old wallet
software cannot discover payments to diversified ML-KEM keys.

## Privacy and resource impact

Distinct new addresses no longer carry a shared encapsulation key. Already
issued legacy addresses retain that link, and reuse of any identical address
remains recognizable. Each action gains a 1,088-byte KEM ciphertext. Compact
blocks gain the same per-action KEM ciphertext. Diversified-address scanning
tries the legacy key and every address key in the wallet's configured range on
every action, including actions not owned by the wallet. Its cost grows with
the number of addresses and actions. No public key identifier or classical
routing hint is added. The implementation must enforce the existing
action-count and block-size limits and should benchmark scan and bandwidth
costs before activation.

Removing sender recovery removes 1,264 bytes from each full action, but it does
not reduce compact-action bytes because they did not include that field.

## Failure behavior

ML-KEM decapsulation uses implicit rejection: malformed-but-correctly-sized
ciphertexts produce a pseudorandom shared secret. coin ownership is determined
by the AEAD tag, then by parsing and matching the coin commitment. Wrong-sized
encodings are rejected by the decoder. Recipient ciphertext is authenticated
and binds the coin commitment and KEM ciphertext.

## Review and open requirements

Before activation, obtain independent protocol and cryptography reviews, add
canonical address/action/compact encoding vectors, check maximum serialized
block resource bounds, and benchmark node and wallet scan costs. The current
proposal leaves spend signatures, curve-based commitments, nullifiers, and the
proof system unchanged; a fully post-quantum shielded pool is out of scope.
