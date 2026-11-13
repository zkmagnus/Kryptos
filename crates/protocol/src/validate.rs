//! Stateless transaction validation.
//!
//! Stateless means: everything that can be checked from the transaction
//! bytes alone, including the proof. Anchor validity and nullifier
//! freshness belong to the chain layer.

use std::collections::BTreeSet;

use crypto::signature::{BatchVerifier, BindingVerificationKey};
use rand_core::{CryptoRng, RngCore};
use systemcall_proof::{ProofBatch, VerifyingKey};

use crate::consensus::{is_action_class, proof_len, BranchId, TX_VERSION};
use crate::transaction::Transaction;
use crate::{Error, Result};

/// Checks shape rules: version, action class, proof length, and unique
/// nullifiers.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] naming the first violated rule.
pub fn check_structure(tx: &Transaction) -> Result<()> {
    check_shape_and_program(tx, crate::consensus::TRANSFER_ENTRYPOINT)?;
    Ok(())
}

/// Checks the structural shape used by kernel-created coinbases.
///
/// This must only be called after the chain kernel has classified the
/// transaction as a coinbase and computed its public balance.
pub fn check_coinbase_structure(tx: &Transaction) -> Result<()> {
    check_shape_and_program(tx, crate::consensus::COINBASE_ENTRYPOINT)
}

fn check_shape_and_program(tx: &Transaction, entrypoint: u16) -> Result<()> {
    if tx.version() != TX_VERSION {
        return Err(Error::InvalidTransaction("unknown version"));
    }
    if tx.entrypoint() != entrypoint {
        return Err(Error::InvalidTransaction("unknown SystemCall target"));
    }
    program_vm::decode(tx.opcode(), &[])
        .map_err(|_| Error::InvalidTransaction("unknown SystemCall opcode"))?;
    if tx.private_proof_v2().is_none() {
        return Err(Error::InvalidTransaction("V2 proof envelope is missing"));
    }
    if !is_action_class(tx.actions().len()) {
        return Err(Error::InvalidTransaction(
            "action count is not an allowed class",
        ));
    }
    if tx.proof().as_bytes().len() != proof_len(tx.actions().len())? {
        return Err(Error::InvalidTransaction(
            "proof length does not match action count",
        ));
    }
    let mut seen = BTreeSet::new();
    if !tx.nullifiers().all(|nf| seen.insert(*nf)) {
        return Err(Error::InvalidTransaction("duplicate nullifier"));
    }
    Ok(())
}

/// The public value balance of a coinbase paying `credit` (subsidy plus
/// the block-producer outputs of other transactions): it creates value.
///
/// # Errors
/// If `credit` does not fit an `i64`.
pub fn coinbase_balance(credit: crate::amount::Amount) -> Result<i64> {
    credit
        .to_i64()?
        .checked_neg()
        .ok_or(Error::AmountOutOfRange)
}

/// Queues every transaction signature into `batch` for later verification.
/// `balance` is the public value balance the binding signature must prove;
/// `branch` is the consensus branch in force where the transaction is being
/// validated, which the signatures must have been made for.
///
/// # Errors
/// Fails if the binding verification key cannot be derived.
pub fn queue_signatures(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    let sighash = tx.sighash(branch);
    queue_spend_auth_signatures(tx, branch, batch);
    let bvk = BindingVerificationKey::from_commitments(tx.value_commitments(), balance)?;
    batch.queue_binding(&bvk, tx.binding_signature(), &sighash);
    Ok(())
}

/// Queues only the per-action spend authorization signatures. This is used
/// for block validation, where value conservation is proven once by the
/// block-wide binding signature rather than by public per-transaction fees.
pub fn queue_spend_auth_signatures(tx: &Transaction, branch: BranchId, batch: &mut BatchVerifier) {
    let sighash = tx.sighash(branch);
    for action in tx.actions() {
        batch.queue_spend_auth(action.body().rk(), action.spend_auth_sig(), &sighash);
    }
}

/// Queues signatures for an ordinary transfer using its attached relay fee.
pub fn queue_transfer_signatures(
    tx: &Transaction,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    queue_signatures(tx, tx.fee().to_i64()?, branch, batch)
}

/// Queues the proof of `tx` into `batch` for later verification.
///
/// # Errors
/// Fails if an action carries a non-canonical point.
pub fn queue_proof(tx: &Transaction, batch: &mut ProofBatch) -> Result<()> {
    if tx.private_proof_v2().is_none() {
        return Err(Error::InvalidTransaction("V2 proof envelope is missing"));
    }
    Ok(batch.add(tx.proof(), &tx.public_inputs()?)?)
}

/// Verifies the V2 proof of one transaction on its own.
///
/// # Errors
/// Returns [`systemcall_proof::Error::InvalidProof`] if the proof is wrong.
pub fn verify_proof(tx: &Transaction, vk: &VerifyingKey) -> Result<()> {
    tx.private_proof_v2()
        .ok_or(Error::InvalidTransaction("V2 proof envelope is missing"))?
        .verify(vk, &tx.public_inputs()?)?;
    Ok(())
}

/// Verifies using the public balance computed by the calling SystemCall or
/// consensus-created operation.
///
/// # Errors
/// Returns the first violation found.
pub fn verify_with_balance(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    check_structure(tx)?;
    verify_authorization_and_proof(tx, balance, branch, vk, rng)
}

/// Verifies a kernel-classified coinbase with its kernel-chosen balance.
pub fn verify_coinbase_with_balance(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    check_coinbase_structure(tx)?;
    verify_authorization_and_proof(tx, balance, branch, vk, rng)
}

fn verify_authorization_and_proof(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    let mut batch = BatchVerifier::new();
    queue_signatures(tx, balance, branch, &mut batch)?;
    batch.verify(rng)?;
    verify_proof(tx, vk)
}

#[cfg(test)]
mod tests {
    use crypto::signature::BindingSignature;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use systemcall_proof::PrivateTransactionProofV2;

    use super::*;
    use crate::action::tests::sample_action;
    use crate::action::ACTION_BODY_LEN;
    use crate::bytes::Encodable;
    use crate::test_keys;
    use crate::transaction::tests::{dummy_proof, sample_anchor};

    fn unsigned_tx(seed: u64, count: usize) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let actions = (0..count).map(|_| sample_action(&mut rng, b"x")).collect();
        let action_proof = if proof_len(count).is_err() {
            crate::transaction::Proof::from_bytes(vec![0])
        } else {
            dummy_proof(count)
        };
        let v2_proof = PrivateTransactionProofV2::new(&action_proof).unwrap();
        Transaction::new(
            sample_anchor(),
            crate::amount::Amount::ZERO,
            actions,
            v2_proof,
            BindingSignature::from_bytes([0; 64]),
        )
        .unwrap()
    }

    #[test]
    fn structure_accepts_every_class() {
        for class in [2, 4, 8, 16] {
            assert!(check_structure(&unsigned_tx(1, class)).is_ok());
        }
    }

    #[test]
    fn structure_rejects_bad_action_counts() {
        for count in [0, 1, 3, 17] {
            assert!(matches!(
                check_structure(&unsigned_tx(2, count)),
                Err(Error::InvalidTransaction(
                    "action count is not an allowed class"
                ))
            ));
        }
    }

    #[test]
    fn structure_rejects_wrong_proof_length() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let actions = (0..2).map(|_| sample_action(&mut rng, b"x")).collect();
        let v2_proof = PrivateTransactionProofV2::new(&dummy_proof(4)).unwrap();
        let tx = Transaction::new(
            sample_anchor(),
            crate::amount::Amount::ZERO,
            actions,
            v2_proof,
            BindingSignature::from_bytes([0; 64]),
        )
        .unwrap();
        assert!(matches!(
            check_structure(&tx),
            Err(Error::InvalidTransaction(
                "proof length does not match action count"
            ))
        ));
    }

    #[test]
    fn structure_rejects_unknown_version() {
        let mut bytes = unsigned_tx(3, 2).to_vec();
        bytes[0] = TX_VERSION.wrapping_add(1);
        assert!(Transaction::from_slice(&bytes).is_err());
    }

    #[test]
    fn structure_rejects_duplicate_nullifiers() {
        let tx = unsigned_tx(4, 2);
        let mut bytes = tx.to_vec();
        let first = 1 + 1 + 2 + 32 + 1;
        let second = first + ACTION_BODY_LEN;
        let nf: Vec<u8> = bytes[first..first + 32].to_vec();
        bytes[second..second + 32].copy_from_slice(&nf);
        let dup = Transaction::from_slice(&bytes).unwrap();
        assert!(matches!(
            check_structure(&dup),
            Err(Error::InvalidTransaction("duplicate nullifier"))
        ));
    }

    #[test]
    fn signatures_over_the_wrong_message_fail() {
        // sample_action signs "x", not the real sighash.
        let tx = unsigned_tx(5, 2);
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let balance = crate::amount::Amount::from_raw(20_000)
            .unwrap()
            .to_i64()
            .unwrap();
        assert!(matches!(
            verify_with_balance(
                &tx,
                balance,
                BranchId::new(1),
                test_keys::verifying_key(),
                &mut rng
            ),
            Err(Error::Crypto(crypto::Error::InvalidSignature))
        ));
    }

    #[test]
    fn zero_proof_is_rejected_even_with_valid_structure() {
        let tx = unsigned_tx(7, 2);
        assert!(matches!(
            verify_proof(&tx, test_keys::verifying_key()),
            Err(Error::Circuit(systemcall_proof::Error::InvalidProof))
        ));
        let mut batch = ProofBatch::new();
        queue_proof(&tx, &mut batch).unwrap();
        assert!(batch.verify(test_keys::verifying_key()).is_err());
    }
}
