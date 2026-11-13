//! Static dispatcher for protocol-defined SystemCall operations.
//!
//! The dispatcher ABI supports the built-in Transfer operation. Current
//! transactions carry the transfer opcode and all checks delegate to the
//! protocol validator so this crate does not introduce separate consensus
//! rules.

use crypto::signature::BatchVerifier;
use protocol::consensus::BranchId;
use protocol::note::ExtractedNoteCommitment;
use protocol::nullifier::Nullifier;
use protocol::transaction::Transaction;
use protocol::{Error, Result};
use rand_core::{CryptoRng, RngCore};
use systemcall_proof::{ProofBatch, VerifyingKey};

/// A transaction selected by its encoded SystemCall opcode.
#[derive(Clone, Copy, Debug)]
pub struct SystemCall<'a> {
    transaction: &'a Transaction,
}

/// Public state effects derived from an accepted transfer's canonical
/// transaction body. This is a read-only request to the kernel; it does not
/// apply or authorize any chain state change by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferEffects {
    /// Nullifiers in action order, to be checked for freshness by the kernel.
    pub nullifiers: Vec<Nullifier>,
    /// Note commitments in action order, to be appended only after the full
    /// transaction or block has passed validation.
    pub commitments: Vec<ExtractedNoteCommitment>,
}

impl<'a> SystemCall<'a> {
    /// Dispatches from the opcode encoded in the transaction.
    ///
    /// Only the shielded transfer opcode is currently supported.
    pub fn dispatch(tx: &'a Transaction) -> Result<Self> {
        program_vm::decode(tx.opcode(), &[])
            .map(|_| Self { transaction: tx })
            .map_err(|_| Error::InvalidTransaction("unknown SystemCall opcode"))
    }

    /// Checks transaction shape and operation-specific structural rules.
    ///
    /// # Errors
    /// Returns the protocol validation error for malformed transactions.
    pub fn check_structure(self) -> Result<()> {
        protocol::validate::check_structure(self.transaction)
    }

    /// Checks the shape for a transaction already identified by the
    /// kernel as a coinbase. Ordinary callers must use [`Self::check_structure`].
    pub fn check_coinbase_structure(self) -> Result<()> {
        protocol::validate::check_coinbase_structure(self.transaction)
    }

    /// Queues spend and binding signatures for batch verification.
    ///
    /// # Errors
    /// Fails if the binding verification key cannot be derived.
    pub fn queue_signatures(self, branch: BranchId, batch: &mut BatchVerifier) -> Result<()> {
        self.check_structure()?;
        protocol::validate::queue_transfer_signatures(self.transaction, branch, batch)
    }

    /// Queues signatures for a kernel-created call whose public balance is
    /// chosen by block accounting, such as coinbase.
    pub fn queue_coinbase_signatures(
        self,
        balance: i64,
        branch: BranchId,
        batch: &mut BatchVerifier,
    ) -> Result<()> {
        self.check_coinbase_structure()?;
        protocol::validate::queue_signatures(self.transaction, balance, branch, batch)
    }

    /// Queues the operation proof for batch verification.
    ///
    /// # Errors
    /// Fails if public inputs cannot be derived from the transaction.
    pub fn queue_proof(self, batch: &mut ProofBatch) -> Result<()> {
        protocol::validate::queue_proof(self.transaction, batch)
    }

    /// Performs the stateless checks for a regular transfer.
    ///
    /// # Errors
    /// Returns the first structural, signature, or proof violation.
    pub fn verify(
        self,
        branch: BranchId,
        vk: &VerifyingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        protocol::validate::verify_with_balance(
            self.transaction,
            self.transaction.fee().to_i64()?,
            branch,
            vk,
            rng,
        )
    }

    /// Verifies a kernel-classified coinbase against its computed credit.
    pub fn verify_coinbase_with_balance(
        self,
        balance: i64,
        branch: BranchId,
        vk: &VerifyingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        self.check_coinbase_structure()?;
        protocol::validate::verify_coinbase_with_balance(self.transaction, balance, branch, vk, rng)
    }

    /// The transaction carried by this operation.
    pub fn transaction(self) -> &'a Transaction {
        self.transaction
    }

    /// Derives the state effects requested by this call from its transaction.
    ///
    /// These values come from canonical action bodies; callers cannot supply
    /// an alternate effects list. The kernel must still verify the proof,
    /// check anchors and nullifier freshness, and apply effects atomically.
    pub fn effects(self) -> TransferEffects {
        TransferEffects {
            nullifiers: self.transaction.nullifiers().copied().collect(),
            commitments: self
                .transaction
                .actions()
                .iter()
                .map(|action| *action.body().cmx())
                .collect(),
        }
    }
}

/// Error type used by the dispatcher API.
pub type DispatchError = Error;

#[cfg(test)]
mod tests {
    use crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
    use crypto::merkle::MerkleTree;
    use protocol::address::RhombusAddress;
    use protocol::builder::{Builder, OutputInfo, SpendInfo};
    use protocol::bytes::Encodable;
    use protocol::coin::Rhombus;
    use protocol::consensus::BranchId;
    use protocol::memo::Memo;
    use protocol::note::{Note, RandomSeed, Rho};
    use protocol::transaction::{Anchor, Transaction};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use systemcall_proof::{ProvingKey, VerifyingKey};

    use super::*;

    fn transfer_fixture(seed: u64) -> (ChaCha20Rng, ProvingKey, VerifyingKey, Transaction) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = RhombusAddress::derive(&fvk, Diversifier::random(&mut rng)).unwrap();
        let note = Note::new(
            address,
            Rhombus::from_raw(100_000).unwrap(),
            Rho::random(&mut rng),
            RandomSeed::random(&mut rng),
        );
        let mut tree = MerkleTree::new();
        let position = tree.append(*note.cmx().unwrap().inner()).unwrap();
        let anchor = Anchor::from_base(tree.root());
        let spend = SpendInfo::new(sk, note, tree.path(position).unwrap());
        let output = Rhombus::from_raw(100_000).unwrap();
        let mut builder = Builder::new(anchor);
        builder
            .add_spend(spend)
            .unwrap()
            .add_output(OutputInfo::new(address, output, Memo::empty(), None))
            .unwrap();
        let pk = ProvingKey::build().unwrap();
        let vk = pk.verifying_key();
        let tx = builder.build(&pk, BranchId::new(1), &mut rng).unwrap();
        (rng, pk, vk, tx)
    }

    #[test]
    fn transfer_effects_are_derived_from_actions_in_order() {
        let (_, _, _, tx) = transfer_fixture(81);
        let effects = SystemCall::dispatch(&tx).unwrap().effects();
        assert_eq!(
            effects.nullifiers,
            tx.nullifiers().copied().collect::<Vec<_>>()
        );
        assert_eq!(
            effects.commitments,
            tx.actions()
                .iter()
                .map(|action| *action.body().cmx())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn transfer_proof_verification_matches_protocol_reference() {
        let (mut rng, _, vk, tx) = transfer_fixture(82);
        let branch = BranchId::new(1);
        let result = SystemCall::dispatch(&tx)
            .unwrap()
            .verify(branch, &vk, &mut rng);
        assert_eq!(
            result,
            protocol::validate::verify_with_balance(&tx, 0, branch, &vk, &mut rng,)
        );
        assert!(result.is_ok());

        let public = tx.public_inputs().unwrap();
        assert_eq!(public.len(), tx.actions().len());
        assert!(public
            .iter()
            .all(|inputs| inputs.cv_net_total == public[0].cv_net_total));
    }

    #[test]
    fn tampered_proof_is_rejected_by_both_dispatch_paths() {
        let (mut rng, _, vk, tx) = transfer_fixture(83);
        let mut bytes = tx.to_vec();
        let proof_offset = 1 + 1 + 2 + 32 + 1 + tx.actions().len() * protocol::action::ACTION_LEN;
        // Preserve the V2 domain marker and alter the first action-proof byte.
        bytes[proof_offset + 4] ^= 1;
        let tampered = Transaction::from_slice(&bytes).unwrap();
        let branch = BranchId::new(1);
        let dispatched = SystemCall::dispatch(&tampered)
            .unwrap()
            .verify(branch, &vk, &mut rng);
        let reference =
            protocol::validate::verify_with_balance(&tampered, 0, branch, &vk, &mut rng);
        assert_eq!(dispatched, reference);
        assert!(dispatched.is_err());
    }

    #[test]
    fn transfer_dispatches_from_the_wire_opcode() {
        let (mut rng, _, vk, tx) = transfer_fixture(84);
        SystemCall::dispatch(&tx)
            .unwrap()
            .verify(BranchId::new(1), &vk, &mut rng)
            .unwrap();
        assert_eq!(tx.version(), protocol::consensus::TX_VERSION);
        assert_eq!(tx.opcode(), protocol::consensus::TRANSFER_OPCODE);
        assert_eq!(tx.entrypoint(), protocol::consensus::TRANSFER_ENTRYPOINT);
    }

    #[test]
    fn v3_transaction_has_no_settlement_data() {
        let (_, _, _, tx) = transfer_fixture(85);
        assert_eq!(tx.proof_size(), tx.proof().as_bytes().len() + 4);
        assert!(protocol::validate::check_structure(&tx).is_ok());
    }
}
