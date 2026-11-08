//! The transaction: a fixed-shape bundle of actions, a public fee, a proof
//! envelope and one binding signature. It tags its action proof with `RHV1`.
//!
//! ```text
//! effecting data = version || program || program_version || entrypoint ||
//!                  anchor || n_actions || fee || action bodies
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
//! or an action-proof length. The V1 format carries an explicit public fee
//! and uses a fixed-size action proof with a four-byte V1 marker.

use crypto::commitment::ValueCommitment;
use crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use crypto::hash::{blake2b_short, SHORT_OUTPUT_LEN, SIGHASH, TXID};
use crypto::pallas;
use systemcall_circuit::PublicInputs;

use crate::consensus::BranchId;
use crypto::signature::BindingSignature;

use crate::action::{Action, ActionBody};
use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{
    proof_len, TRANSFER_ENTRYPOINT, TRANSFER_PROGRAM_ID, TRANSFER_PROGRAM_VERSION, TX_VERSION,
};
use crate::nullifier::Nullifier;
use crate::Result;

/// The root of the note commitment tree a transaction spends against.
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

use systemcall_proof::PrivateTransactionProofV1;
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
    program_id: [u8; 32],
    program_version: u16,
    entrypoint: u16,
    anchor: Anchor,
    fee: crate::coin::Rhombus,
    actions: Vec<Action>,
    proof: Proof,
    binding_signature: BindingSignature,
}

impl Transaction {
    /// Assembles a transaction using the current V1 proof envelope.
    pub fn new(
        anchor: Anchor,
        fee: crate::coin::Rhombus,
        actions: Vec<Action>,
        proof: PrivateTransactionProofV1,
        binding_signature: BindingSignature,
    ) -> Result<Self> {
        let action_proof = proof.proof()?;
        Ok(Self {
            version: TX_VERSION,
            program_id: TRANSFER_PROGRAM_ID,
            program_version: TRANSFER_PROGRAM_VERSION,
            entrypoint: TRANSFER_ENTRYPOINT,
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

    /// Program identity carried by the SystemCall envelope.
    pub fn program_id(&self) -> &[u8; 32] {
        &self.program_id
    }

    /// Program semantic/verifier version.
    pub fn program_version(&self) -> u16 {
        self.program_version
    }

    /// Program entrypoint selector.
    pub fn entrypoint(&self) -> u16 {
        self.entrypoint
    }

    /// The complete version-1 proof envelope.
    pub fn private_proof_v1(&self) -> Option<PrivateTransactionProofV1> {
        (self.program_version == TRANSFER_PROGRAM_VERSION)
            .then(|| PrivateTransactionProofV1::new(&self.proof).ok())
            .flatten()
    }

    /// The anchor.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The sender's public fee offer.
    pub fn fee(&self) -> crate::coin::Rhombus {
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
    /// V1 includes its envelope marker.
    pub fn proof_size(&self) -> usize {
        self.private_proof_v1().map_or_else(
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
        self.actions
            .iter()
            .map(|a| a.body().public_inputs(&self.anchor))
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
            &self.program_id,
            self.program_version,
            self.entrypoint,
            &self.anchor,
            self.fee,
            &bodies,
        )
    }
}

/// The effecting data of a transaction: everything but proof and
/// signatures. Shared by [`Transaction`] and by the builder, which needs
/// the sighash before any signature exists.
fn effecting_bytes(
    version: u8,
    program_id: &[u8; 32],
    program_version: u16,
    entrypoint: u16,
    anchor: &Anchor,
    fee: crate::coin::Rhombus,
    bodies: &[&ActionBody],
) -> Vec<u8> {
    let mut w = Writer::default();
    write_header(
        &mut w,
        version,
        program_id,
        program_version,
        entrypoint,
        anchor,
        fee,
        bodies.len(),
    );
    for body in bodies {
        body.write(&mut w);
    }
    w.into_bytes()
}

/// The sighash for a transfer under `branch`.
pub fn sighash_of(
    anchor: &Anchor,
    bodies: &[&ActionBody],
    fee: crate::coin::Rhombus,
    branch: BranchId,
) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        SIGHASH,
        &[
            &effecting_bytes(
                TX_VERSION,
                &TRANSFER_PROGRAM_ID,
                TRANSFER_PROGRAM_VERSION,
                TRANSFER_ENTRYPOINT,
                anchor,
                fee,
                bodies,
            ),
            &branch.to_bytes(),
        ],
    )
}

fn write_header(
    w: &mut Writer,
    version: u8,
    program_id: &[u8; 32],
    program_version: u16,
    entrypoint: u16,
    anchor: &Anchor,
    fee: crate::coin::Rhombus,
    actions: usize,
) {
    // Bounded by MAX_ACTIONS in valid transactions; the clamp keeps the
    // encoding total for anything else, and validation rejects it.
    let count = u8::try_from(actions).unwrap_or(u8::MAX);
    w.put_u8(version)
        .put(program_id)
        .put(&program_version.to_le_bytes())
        .put(&entrypoint.to_le_bytes());
    anchor.write(w);
    w.put_u8(count);
    w.put(&fee.to_le_bytes());
}

impl Encodable for Transaction {
    fn write(&self, w: &mut Writer) {
        write_header(
            w,
            self.version,
            &self.program_id,
            self.program_version,
            self.entrypoint,
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
        if let Some(proof) = self.private_proof_v1() {
            w.put(proof.as_bytes());
        }
        w.put(&self.binding_signature.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        let program_id = r.take_array()?;
        let program_version = u16::from_le_bytes(r.take_array()?);
        let entrypoint = u16::from_le_bytes(r.take_array()?);
        if program_version != TRANSFER_PROGRAM_VERSION
            || program_id != TRANSFER_PROGRAM_ID
            || entrypoint != TRANSFER_ENTRYPOINT
        {
            return Err(crate::Error::Malformed("unsupported Transfer V1 identity"));
        }
        let anchor = Anchor::read(r)?;
        let count = usize::from(r.take_u8()?);
        let fee = crate::coin::Rhombus::from_raw(r.take_u64_le()?)?;
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
            .ok_or(crate::Error::Malformed("invalid v1 proof length"))?;
        let bytes = r.take(len)?.to_vec();
        let proof = PrivateTransactionProofV1::from_bytes(bytes)
            .and_then(|v1| v1.proof())
            .map_err(|_| crate::Error::Malformed("invalid v1 transaction proof"))?;
        let binding_signature = BindingSignature::from_bytes(r.take_array()?);
        Ok(Self {
            version,
            program_id,
            program_version,
            entrypoint,
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
            crate::coin::Rhombus::ZERO,
            actions,
            PrivateTransactionProofV1::new(&dummy_proof(count)).unwrap(),
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
            1 + 32
                + 2
                + 2
                + 32
                + 1
                + 8
                + 2 * ACTION_BODY_LEN
                + 2 * 64
                + 4
                + proof_len(2).unwrap()
                + 64
        );
        assert_eq!(Transaction::from_slice(&bytes), Ok(tx));
    }

    #[test]
    fn txid_ignores_signatures_and_proof() {
        let tx = sample_transaction(2, 2);
        let mut bytes = tx.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1; // binding signature
        let first_sig = 78 + 2 * ACTION_BODY_LEN;
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
        bytes[1] ^= 1; // program ID
        let altered = Transaction::from_slice(&bytes).unwrap();
        assert_ne!(altered.txid(), tx.txid());
    }

    #[test]
    fn parser_rejects_previous_transfer_program_identity() {
        let mut bytes = sample_transaction(11, 2).to_vec();
        bytes[1..33].copy_from_slice(b"RHOMBUS\0TRANSFER\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
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
            sighash_of(tx.anchor(), &bodies, tx.fee(), BranchId::new(1)),
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
