//! The transaction: a fixed-shape bundle of actions, a proof
//! envelope and one binding signature. Transfers are native chain
//! transactions; the action proof envelope is tagged with `RHA1`.
//!
//! ```text
//! effecting data = version || kind || anchor || fee || n_actions ||
//!                  action bodies
//! txid           = BLAKE2b-256_{TXID}(effecting data)
//! sighash        = BLAKE2b-256_{SIGHASH}(effecting data || branch id)
//! encoding       = effecting data || spend signatures || proof || binding sig
//! ```
//!
//! The txid excludes the proof and every signature, so re-randomizing
//! either cannot change the id. The sighash additionally binds the
//! [`BranchId`] of the consensus rules the transaction is meant for, so
//! it is not replayable across a fork or between networks; the branch is
//! not encoded, validation supplies it. There is no locktime, expiry,
//! or an action-proof length.

use crypto::commitment::ValueCommitment;
use crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use crypto::hash::{blake2b_short, SHORT_OUTPUT_LEN, SIGHASH, TXID};
use crypto::pallas;
use transaction_circuit::PublicInputs;

use crate::consensus::BranchId;
use crypto::signature::BindingSignature;

use crate::action::{Action, ActionBody, ACTION_BODY_LEN};
use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{proof_len, COINBASE_KIND, TRANSFER_KIND, TX_VERSION};
use crate::nullifier::Nullifier;
use crate::Result;

/// Fixed transaction header length, excluding actions, proof, and signature.
const TRANSACTION_HEADER_LEN: usize = 1 + 1 + 32 + 8 + 1;

/// The root of the coin commitment tree a transaction spends against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor(pallas::Base);

impl Anchor {
    /// Wraps a tree root.
    pub const fn from_base(root: pallas::Base) -> Self {
        Self(root)
    }

    /// The tree root.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0)
    }
}

impl Encodable for Anchor {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(base_from_bytes(&r.take_array()?)?))
    }
}

use transaction_proof::ActionProofEnvelope;
pub use transaction_proof::{Proof, ACTION_PROOF_MAGIC};

/// A transaction identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxId([u8; SHORT_OUTPUT_LEN]);

impl TxId {
    /// Wraps raw bytes, as received from the network.
    pub fn from_bytes(bytes: [u8; SHORT_OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; SHORT_OUTPUT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TxId({self})")
    }
}

impl core::fmt::Display for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&crypto::encoding::to_hex(&self.0))
    }
}

/// A complete transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    version: u8,
    kind: u8,
    anchor: Anchor,
    fee: crate::amount::RawCoin,
    actions: Vec<Action>,
    proof: Proof,
    binding_signature: BindingSignature,
}

impl Transaction {
    /// Exact encoded size for a transaction with an allowed action class.
    /// Includes the four-byte proof envelope marker and all signatures.
    ///
    /// # Errors
    /// Returns the protocol error when `actions` is not an allowed class.
    pub fn encoded_len_for_actions(actions: usize) -> Result<usize> {
        let action_proof_len = proof_len(actions)?;
        TRANSACTION_HEADER_LEN
            .checked_add(
                actions
                    .checked_mul(ACTION_BODY_LEN + crypto::signature::SIGNATURE_LEN)
                    .ok_or(crate::Error::Malformed("transaction size overflow"))?,
            )
            .and_then(|len| {
                len.checked_add(
                    action_proof_len + ACTION_PROOF_MAGIC.len() + crypto::signature::SIGNATURE_LEN,
                )
            })
            .ok_or(crate::Error::Malformed("transaction size overflow"))
    }

    /// Fee rate applied to the exact encoding size for this action class.
    /// Kept as a convenience for builders that know the final action class.
    pub fn default_fee_for_actions(actions: usize) -> Result<crate::amount::RawCoin> {
        crate::fee::fee_for_len(Self::encoded_len_for_actions(actions)?)
    }

    /// Exact size of this transaction's canonical encoding.
    pub fn encoded_len(&self) -> usize {
        self.to_vec().len()
    }

    /// Checks that a transfer pays its encoded size and a coinbase pays zero.
    pub fn check_fee(&self) -> Result<()> {
        let required = if self.kind == COINBASE_KIND {
            crate::amount::RawCoin::ZERO
        } else {
            crate::fee::fee_for_len(self.encoded_len())?
        };
        if self.fee == required {
            Ok(())
        } else {
            Err(crate::Error::InvalidTransaction(
                "fee does not match transaction size",
            ))
        }
    }

    /// Assembles a transaction using an action proof envelope.
    pub fn new(
        anchor: Anchor,
        fee: crate::amount::RawCoin,
        actions: Vec<Action>,
        proof: ActionProofEnvelope,
        binding_signature: BindingSignature,
    ) -> Result<Self> {
        Self::new_with_kind(
            anchor,
            fee,
            actions,
            proof,
            binding_signature,
            TRANSFER_KIND,
        )
    }

    /// Assembles a coinbase transaction using the negative aggregate-net mode.
    pub fn new_coinbase(
        anchor: Anchor,
        actions: Vec<Action>,
        proof: ActionProofEnvelope,
        binding_signature: BindingSignature,
    ) -> Result<Self> {
        Self::new_with_kind(
            anchor,
            crate::amount::RawCoin::ZERO,
            actions,
            proof,
            binding_signature,
            COINBASE_KIND,
        )
    }

    fn new_with_kind(
        anchor: Anchor,
        fee: crate::amount::RawCoin,
        actions: Vec<Action>,
        proof: ActionProofEnvelope,
        binding_signature: BindingSignature,
        kind: u8,
    ) -> Result<Self> {
        let action_proof = proof.proof()?;
        Ok(Self {
            version: TX_VERSION,
            kind,
            anchor,
            fee,
            actions,
            proof: action_proof,
            binding_signature,
        })
    }

    /// The version byte.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Native chain transaction kind.
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// The complete action proof envelope.
    pub fn action_proof_envelope(&self) -> Option<ActionProofEnvelope> {
        (self.kind == TRANSFER_KIND || self.kind == COINBASE_KIND)
            .then(|| ActionProofEnvelope::new(&self.proof).ok())
            .flatten()
    }

    /// The anchor.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The declared public fee.
    pub fn fee(&self) -> crate::amount::RawCoin {
        self.fee
    }

    /// The actions.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The proof.
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// The number of serialized bytes used by this transaction's proof data.
    /// Includes the envelope marker when present.
    pub fn proof_size(&self) -> usize {
        self.action_proof_envelope().map_or_else(
            || self.proof.as_bytes().len(),
            |proof| proof.as_bytes().len(),
        )
    }

    /// The binding signature.
    pub fn binding_signature(&self) -> &BindingSignature {
        &self.binding_signature
    }

    /// Every nullifier revealed, in action order.
    pub fn nullifiers(&self) -> impl Iterator<Item = &Nullifier> {
        self.actions.iter().map(|a| a.body().nullifier())
    }

    /// The circuit public inputs of every action, in action order.
    ///
    /// # Errors
    /// Fails if an action carries a non-canonical point.
    pub fn public_inputs(&self, coinbase: bool) -> Result<Vec<PublicInputs>> {
        let total = ValueCommitment::sum(self.value_commitments());
        let net_sign = if coinbase {
            -pallas::Base::one()
        } else {
            pallas::Base::one()
        };
        self.actions
            .iter()
            .map(|a| {
                a.body()
                    .public_inputs(&self.anchor, *total.as_point(), net_sign)
            })
            .collect()
    }

    /// Every net value commitment, in action order.
    pub fn value_commitments(&self) -> impl Iterator<Item = &ValueCommitment> {
        self.actions.iter().map(|a| a.body().cv_net())
    }

    /// The transaction id.
    pub fn txid(&self) -> TxId {
        TxId(blake2b_short(TXID, &[&self.effecting_bytes()]))
    }

    /// The message every signature in this transaction signs, under the
    /// consensus rules identified by `branch`.
    pub fn sighash(&self, branch: BranchId) -> [u8; SHORT_OUTPUT_LEN] {
        blake2b_short(SIGHASH, &[&self.effecting_bytes(), &branch.to_bytes()])
    }

    fn effecting_bytes(&self) -> Vec<u8> {
        let bodies: Vec<&ActionBody> = self.actions.iter().map(Action::body).collect();
        effecting_bytes(self.version, self.kind, &self.anchor, self.fee, &bodies)
    }
}

/// The effecting data of a transaction: everything but proof and
/// signatures. Shared by [`Transaction`] and by the builder, which needs
/// the sighash before any signature exists.
fn effecting_bytes(
    version: u8,
    kind: u8,
    anchor: &Anchor,
    fee: crate::amount::RawCoin,
    bodies: &[&ActionBody],
) -> Vec<u8> {
    let mut w = Writer::default();
    write_header(&mut w, version, kind, anchor, fee, bodies.len());
    for body in bodies {
        body.write(&mut w);
    }
    w.into_bytes()
}

/// The sighash for a transfer under `branch`.
pub fn sighash_of(
    anchor: &Anchor,
    bodies: &[&ActionBody],
    kind: u8,
    fee: crate::amount::RawCoin,
    branch: BranchId,
) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        SIGHASH,
        &[
            &effecting_bytes(TX_VERSION, kind, anchor, fee, bodies),
            &branch.to_bytes(),
        ],
    )
}

fn write_header(
    w: &mut Writer,
    version: u8,
    kind: u8,
    anchor: &Anchor,
    fee: crate::amount::RawCoin,
    actions: usize,
) {
    // Bounded by MAX_ACTIONS in valid transactions; the clamp keeps the
    // encoding total for anything else, and validation rejects it.
    let count = u8::try_from(actions).unwrap_or(u8::MAX);
    w.put_u8(version).put_u8(kind);
    anchor.write(w);
    w.put(&fee.to_le_bytes());
    w.put_u8(count);
}

impl Encodable for Transaction {
    fn write(&self, w: &mut Writer) {
        write_header(
            w,
            self.version,
            self.kind,
            &self.anchor,
            self.fee,
            self.actions.len(),
        );
        for action in &self.actions {
            action.body().write(w);
        }
        for action in &self.actions {
            w.put(&action.spend_auth_sig().to_bytes());
        }
        if let Some(proof) = self.action_proof_envelope() {
            w.put(proof.as_bytes());
        }
        w.put(&self.binding_signature.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        let kind = r.take_u8()?;
        if version != TX_VERSION || (kind != TRANSFER_KIND && kind != COINBASE_KIND) {
            return Err(crate::Error::Malformed("unknown transaction kind"));
        }
        let anchor = Anchor::read(r)?;
        let fee = crate::amount::RawCoin::from_raw(r.take_u64_le()?)?;
        let count = usize::from(r.take_u8()?);
        let bodies = (0..count)
            .map(|_| ActionBody::read(r))
            .collect::<Result<Vec<_>>>()?;
        let signatures = (0..count)
            .map(|_| r.take_array())
            .collect::<Result<Vec<[u8; crypto::signature::SIGNATURE_LEN]>>>()?;
        let actions = bodies
            .into_iter()
            .zip(signatures)
            .map(|(body, signature)| {
                body.sign(crypto::signature::SpendAuthSignature::from_bytes(signature))
            })
            .collect();
        let len = ACTION_PROOF_MAGIC
            .len()
            .checked_add(proof_len(count)?)
            .ok_or(crate::Error::Malformed("invalid proof envelope length"))?;
        let bytes = r.take(len)?.to_vec();
        let proof = ActionProofEnvelope::from_bytes(bytes)
            .and_then(|envelope| envelope.proof())
            .map_err(|_| crate::Error::Malformed("invalid transaction proof envelope"))?;
        let binding_signature = BindingSignature::from_bytes(r.take_array()?);
        Ok(Self {
            version,
            kind,
            anchor,
            fee,
            actions,
            proof,
            binding_signature,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::action::tests::sample_action;
    use crate::action::ACTION_BODY_LEN;

    pub(crate) fn sample_anchor() -> Anchor {
        Anchor::from_base(pallas::Base::from(7u64))
    }

    /// Zero bytes of the right length: shaped like a proof, verifies as nothing.
    pub(crate) fn dummy_proof(actions: usize) -> Proof {
        Proof::from_bytes(vec![0; proof_len(actions).unwrap_or(0)])
    }

    /// A structurally complete transaction whose signatures are over an
    /// arbitrary message, so it encodes but does not verify.
    pub(crate) fn sample_transaction(seed: u64, count: usize) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let actions = (0..count).map(|_| sample_action(&mut rng, b"x")).collect();
        Transaction::new(
            sample_anchor(),
            crate::fee::fee_for_len(Transaction::encoded_len_for_actions(count).unwrap_or(0))
                .unwrap(),
            actions,
            ActionProofEnvelope::new(&dummy_proof(count)).unwrap(),
            BindingSignature::from_bytes([9; 64]),
        )
        .unwrap()
    }

    #[test]
    fn encoding_roundtrips_with_expected_length() {
        let tx = sample_transaction(1, 2);
        let bytes = tx.to_vec();
        assert_eq!(
            bytes.len(),
            1 + 1 + 32 + 8 + 1 + 2 * ACTION_BODY_LEN + 2 * 64 + 4 + proof_len(2).unwrap() + 64
        );
        assert_eq!(tx.encoded_len(), bytes.len());
        assert_eq!(Transaction::from_slice(&bytes), Ok(tx));
    }

    #[test]
    fn default_fee_is_one_raw_unit_per_encoded_byte() {
        for actions in [2, 4, 8, 16] {
            let fee = Transaction::default_fee_for_actions(actions).unwrap();
            assert_eq!(
                fee.raw() as usize,
                Transaction::encoded_len_for_actions(actions).unwrap()
            );
        }
    }

    #[test]
    fn check_fee_rejects_fee_mismatch() {
        let tx = sample_transaction(30, 2);
        assert!(tx.check_fee().is_ok());
        let mut altered = tx.clone();
        altered.fee = crate::amount::RawCoin::ZERO;
        assert!(altered.check_fee().is_err());
    }

    #[test]
    fn txid_ignores_signatures_and_proof() {
        let tx = sample_transaction(2, 2);
        let mut bytes = tx.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1; // binding signature
        let first_sig = TRANSACTION_HEADER_LEN + 2 * ACTION_BODY_LEN;
        bytes[first_sig] ^= 1; // first spend auth signature
        let altered = Transaction::from_slice(&bytes).unwrap();
        assert_ne!(altered, tx);
        assert_eq!(altered.txid(), tx.txid());
        assert_eq!(
            altered.sighash(BranchId::new(1)),
            tx.sighash(BranchId::new(1))
        );
    }

    #[test]
    fn txid_changes_with_effecting_data() {
        let tx = sample_transaction(3, 2);
        let mut bytes = tx.to_vec();
        bytes[4] ^= 1; // anchor
        let altered = Transaction::from_slice(&bytes).unwrap();
        assert_ne!(altered.txid(), tx.txid());
    }

    #[test]
    fn parser_rejects_unknown_native_kind() {
        let mut bytes = sample_transaction(11, 2).to_vec();
        bytes[1] = 0xff;
        assert!(Transaction::from_slice(&bytes).is_err());
    }

    #[test]
    fn sighash_differs_from_txid() {
        let tx = sample_transaction(4, 2);
        assert_ne!(tx.sighash(BranchId::new(1)), *tx.txid().as_bytes());
        assert_ne!(
            tx.sighash(BranchId::new(1)),
            tx.sighash(BranchId::new(2)),
            "the sighash binds the branch"
        );
        assert_eq!(
            tx.txid(),
            tx.txid(),
            "the txid does not depend on the branch"
        );
        let bodies: Vec<&ActionBody> = tx.actions().iter().map(Action::body).collect();
        assert_eq!(
            sighash_of(
                tx.anchor(),
                &bodies,
                crate::consensus::TRANSFER_KIND,
                tx.fee(),
                BranchId::new(1)
            ),
            tx.sighash(BranchId::new(1))
        );
    }

    #[test]
    fn changing_fee_changes_txid_and_sighash() {
        let tx = sample_transaction(44, 2);
        let bytes = tx.to_vec();
        let mut changed = bytes;
        // Header: version, native kind, anchor, then 8 byte LE fee.
        changed[34] ^= 1;
        let changed = Transaction::from_slice(&changed).unwrap();
        assert_ne!(changed.txid(), tx.txid());
        assert_ne!(
            changed.sighash(BranchId::new(1)),
            tx.sighash(BranchId::new(1))
        );
    }

    #[test]
    fn txid_displays_as_hex() {
        let id = sample_transaction(7, 2).txid();
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(format!("{id:?}"), format!("TxId({text})"));
    }

    #[test]
    fn proof_length_is_fixed_by_the_action_count() {
        let tx = sample_transaction(9, 2);
        let mut bytes = tx.to_vec();
        bytes.pop();
        assert!(Transaction::from_slice(&bytes).is_err(), "one byte short");
        bytes.push(0);
        bytes.push(0);
        assert!(Transaction::from_slice(&bytes).is_err(), "one byte long");
    }

    #[test]
    fn public_inputs_follow_actions() {
        let tx = sample_transaction(10, 2);
        let public = tx.public_inputs(false).unwrap();
        assert_eq!(public.len(), 2);
        assert_eq!(public[0].anchor, *tx.anchor().inner());
        assert_eq!(
            public[1].nf_old,
            tx.actions()[1].body().nullifier().to_base().unwrap()
        );
    }

    #[test]
    fn iterators_follow_action_order() {
        let tx = sample_transaction(8, 4);
        assert_eq!(tx.nullifiers().count(), 4);
        assert_eq!(tx.value_commitments().count(), 4);
        assert_eq!(
            tx.nullifiers().next(),
            Some(tx.actions()[0].body().nullifier())
        );
        assert_eq!(tx.version(), TX_VERSION);
        assert_eq!(tx.proof(), &dummy_proof(4));
        assert_eq!(tx.binding_signature().to_bytes(), [9; 64]);
    }
}
