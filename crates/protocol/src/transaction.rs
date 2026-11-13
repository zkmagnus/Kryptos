//! The transaction: a fixed-shape bundle of actions, a proof
//! envelope and one binding signature. The wire selector is the transfer
//! opcode; the action proof remains tagged with `RHV2`.
//!
//! ```text
//! effecting data = version || opcode || entrypoint || anchor || n_actions ||
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
//! or an action-proof length. Fee openings are carried by transaction relay
//! metadata and are absent from this encoding.

use crypto::commitment::ValueCommitment;
use crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use crypto::hash::{blake2b_short, SHORT_OUTPUT_LEN, SIGHASH, TXID};
use crypto::pallas;
use systemcall_circuit::PublicInputs;

use crate::consensus::BranchId;
use crypto::signature::BindingSignature;

use crate::action::{Action, ActionBody, ACTION_BODY_LEN};
use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{
    proof_len, COINBASE_ENTRYPOINT, TRANSFER_ENTRYPOINT, TRANSFER_OPCODE, TX_VERSION,
};
use crate::nullifier::Nullifier;
use crate::Result;

/// Fee rate used by wallet convenience methods: one raw unit per encoded byte.
pub const DEFAULT_FEE_RATE: u64 = 1;
/// Fixed transaction header length, excluding actions, proof, and signature.
const TRANSACTION_HEADER_LEN: usize = 37;

/// The root of the coin commitment tree a transaction spends against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor(pallas::Base);

impl Anchor {
    /// Wraps a tree root.
    pub fn from_base(root: pallas::Base) -> Self {
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

use systemcall_proof::PrivateTransactionProofV2;
pub use systemcall_proof::Proof;

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
    opcode: u8,
    entrypoint: u16,
    anchor: Anchor,
    fee: crate::amount::RawCoin,
    fee_opening: Option<crate::fee::FeeOpening>,
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
                len.checked_add(action_proof_len + 4 + crypto::signature::SIGNATURE_LEN)
            })
            .ok_or(crate::Error::Malformed("transaction size overflow"))
    }

    /// Default wallet fee for this action class: one raw unit per encoded byte.
    pub fn default_fee_for_actions(actions: usize) -> Result<crate::amount::RawCoin> {
        let bytes = u64::try_from(Self::encoded_len_for_actions(actions)?)
            .map_err(|_| crate::Error::RawCoinOutOfRange)?;
        let raw = bytes
            .checked_mul(DEFAULT_FEE_RATE)
            .ok_or(crate::Error::RawCoinOutOfRange)?;
        crate::amount::RawCoin::from_raw(raw)
    }

    /// Assembles a transaction using the current V2 proof envelope.
    pub fn new(
        anchor: Anchor,
        fee: crate::amount::RawCoin,
        actions: Vec<Action>,
        proof: PrivateTransactionProofV2,
        binding_signature: BindingSignature,
    ) -> Result<Self> {
        Self::new_with_entrypoint(
            anchor,
            fee,
            actions,
            proof,
            binding_signature,
            TRANSFER_ENTRYPOINT,
        )
    }

    /// Assembles a coinbase transaction using the negative aggregate-net mode.
    pub fn new_coinbase(
        anchor: Anchor,
        actions: Vec<Action>,
        proof: PrivateTransactionProofV2,
        binding_signature: BindingSignature,
    ) -> Result<Self> {
        Self::new_with_entrypoint(
            anchor,
            crate::amount::RawCoin::ZERO,
            actions,
            proof,
            binding_signature,
            COINBASE_ENTRYPOINT,
        )
    }

    fn new_with_entrypoint(
        anchor: Anchor,
        fee: crate::amount::RawCoin,
        actions: Vec<Action>,
        proof: PrivateTransactionProofV2,
        binding_signature: BindingSignature,
        entrypoint: u16,
    ) -> Result<Self> {
        let action_proof = proof.proof()?;
        Ok(Self {
            version: TX_VERSION,
            opcode: TRANSFER_OPCODE,
            entrypoint,
            anchor,
            fee,
            fee_opening: None,
            actions,
            proof: action_proof,
            binding_signature,
        })
    }

    /// The version byte.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Program entrypoint selector.
    pub fn entrypoint(&self) -> u16 {
        self.entrypoint
    }

    /// The SystemCall opcode carried by this transaction.
    pub fn opcode(&self) -> u8 {
        self.opcode
    }

    /// The complete version-2 proof envelope.
    pub fn private_proof_v2(&self) -> Option<PrivateTransactionProofV2> {
        (self.opcode == TRANSFER_OPCODE)
            .then(|| PrivateTransactionProofV2::new(&self.proof).ok())
            .flatten()
    }

    /// The anchor.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The fee amount attached from relay metadata. It is zero for a
    /// transaction decoded from a block, which contains no fee opening.
    pub fn fee(&self) -> crate::amount::RawCoin {
        self.fee
    }

    /// The node-only fee opening attached by the builder or relay decoder.
    pub fn fee_opening(&self) -> Option<&crate::fee::FeeOpening> {
        self.fee_opening.as_ref()
    }

    /// Attaches and verifies relay fee metadata in memory. The amount is not
    /// serialized or included in the transaction identifier.
    pub fn with_fee_opening(mut self, opening: &crate::fee::FeeOpening) -> Result<Self> {
        opening.verify(self.value_commitments())?;
        self.fee = opening.fee();
        self.fee_opening = Some(opening.clone());
        Ok(self)
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
    /// V2 includes its envelope marker.
    pub fn proof_size(&self) -> usize {
        self.private_proof_v2().map_or_else(
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
    pub fn public_inputs(&self) -> Result<Vec<PublicInputs>> {
        let total = ValueCommitment::sum(self.value_commitments());
        let net_sign = if self.entrypoint == COINBASE_ENTRYPOINT {
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
        effecting_bytes(
            self.version,
            self.opcode,
            self.entrypoint,
            &self.anchor,
            &bodies,
        )
    }
}

/// The effecting data of a transaction: everything but proof and
/// signatures. Shared by [`Transaction`] and by the builder, which needs
/// the sighash before any signature exists.
fn effecting_bytes(
    version: u8,
    opcode: u8,
    entrypoint: u16,
    anchor: &Anchor,
    bodies: &[&ActionBody],
) -> Vec<u8> {
    let mut w = Writer::default();
    write_header(&mut w, version, opcode, entrypoint, anchor, bodies.len());
    for body in bodies {
        body.write(&mut w);
    }
    w.into_bytes()
}

/// The sighash for a transfer under `branch`.
pub fn sighash_of(
    anchor: &Anchor,
    bodies: &[&ActionBody],
    entrypoint: u16,
    branch: BranchId,
) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        SIGHASH,
        &[
            &effecting_bytes(TX_VERSION, TRANSFER_OPCODE, entrypoint, anchor, bodies),
            &branch.to_bytes(),
        ],
    )
}

fn write_header(
    w: &mut Writer,
    version: u8,
    opcode: u8,
    entrypoint: u16,
    anchor: &Anchor,
    actions: usize,
) {
    // Bounded by MAX_ACTIONS in valid transactions; the clamp keeps the
    // encoding total for anything else, and validation rejects it.
    let count = u8::try_from(actions).unwrap_or(u8::MAX);
    w.put_u8(version)
        .put_u8(opcode)
        .put(&entrypoint.to_le_bytes());
    anchor.write(w);
    w.put_u8(count);
}

impl Encodable for Transaction {
    fn write(&self, w: &mut Writer) {
        write_header(
            w,
            self.version,
            self.opcode,
            self.entrypoint,
            &self.anchor,
            self.actions.len(),
        );
        for action in &self.actions {
            action.body().write(w);
        }
        for action in &self.actions {
            w.put(&action.spend_auth_sig().to_bytes());
        }
        if let Some(proof) = self.private_proof_v2() {
            w.put(proof.as_bytes());
        }
        w.put(&self.binding_signature.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        let opcode = r.take_u8()?;
        let entrypoint = u16::from_le_bytes(r.take_array()?);
        if version != TX_VERSION
            || opcode != TRANSFER_OPCODE
            || (entrypoint != TRANSFER_ENTRYPOINT && entrypoint != COINBASE_ENTRYPOINT)
        {
            return Err(crate::Error::Malformed("unsupported SystemCall opcode"));
        }
        let anchor = Anchor::read(r)?;
        let count = usize::from(r.take_u8()?);
        // A block or standalone transaction contains no fee opening.
        let fee = crate::amount::RawCoin::ZERO;
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
        let len = 4usize
            .checked_add(proof_len(count)?)
            .ok_or(crate::Error::Malformed("invalid v2 proof length"))?;
        let bytes = r.take(len)?.to_vec();
        let proof = PrivateTransactionProofV2::from_bytes(bytes)
            .and_then(|v2| v2.proof())
            .map_err(|_| crate::Error::Malformed("invalid v2 transaction proof"))?;
        let binding_signature = BindingSignature::from_bytes(r.take_array()?);
        Ok(Self {
            version,
            opcode,
            entrypoint,
            anchor,
            fee,
            fee_opening: None,
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
            crate::amount::RawCoin::ZERO,
            actions,
            PrivateTransactionProofV2::new(&dummy_proof(count)).unwrap(),
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
            1 + 1 + 2 + 32 + 1 + 2 * ACTION_BODY_LEN + 2 * 64 + 4 + proof_len(2).unwrap() + 64
        );
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
    fn parser_rejects_unknown_opcode() {
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
            sighash_of(tx.anchor(), &bodies, TRANSFER_ENTRYPOINT, BranchId::new(1),),
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
        let public = tx.public_inputs().unwrap();
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
