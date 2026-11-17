//! Builds a balanced, padded, signed and proven transaction from spends
//! and outputs.
//!
//! Callers choose which coins to spend and what to create. The builder
//! pads to the next action class with dummy actions, shuffles so position
//! reveals nothing, derives every per-action secret, signs once the
//! sighash is known, and proves every action in one action proof wrapped
//! with the V2 domain marker. Input selection and change computation stay
//! in the wallet.

use crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use crypto::keys::{
    Diversifier, FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendingKey,
};
use crypto::merkle::{MerklePath, EMPTY_LEAF, MERKLE_DEPTH};
use crypto::signature::{BindingSigningKey, RandomizedSigningKey, SpendAuthRandomizer};
use rand_core::{CryptoRng, RngCore};
use transaction_circuit::{ActionWitness, CoinWitness, SpendWitness};
use transaction_proof::{PrivateTransactionProofV2, ProvingKey};

use crate::action::{Action, ActionBody};
use crate::address::RhombusAddress;
use crate::amount::{RawCoin, ValueSum};
use crate::coin::{Coin, RandomSeed, Rho};
use crate::consensus::action_class_for;
use crate::consensus::{BranchId, COINBASE_KIND, TRANSFER_KIND};
use crate::encryption::encrypt_coin;
use crate::transaction::{sighash_of, Anchor, Transaction};
use crate::{Error, Result};

/// A coin to spend, the key that can spend it, and its place in the tree.
#[derive(Clone, Debug)]
pub struct SpendInfo {
    sk: SpendingKey,
    coin: Coin,
    path: MerklePath,
}

impl SpendInfo {
    /// A real spend. `path` must lead from the coin's commitment to the
    /// anchor the transaction is built against.
    pub fn new(sk: SpendingKey, coin: Coin, path: MerklePath) -> Self {
        Self { sk, coin, path }
    }

    /// A zero-valued spend of a coin that never existed. Its nullifier is
    /// well formed and unique, and the circuit accepts it because the
    /// value is zero, so the path is never checked.
    ///
    /// # Errors
    /// Fails only if key derivation fails, which has negligible probability.
    pub fn dummy(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let sk = SpendingKey::random(rng);
        let address = random_address(&sk, rng)?;
        let coin = Coin::new(
            *address.diversifier(),
            *address.pk_d(),
            RawCoin::ZERO,
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        Ok(Self {
            sk,
            coin,
            path: MerklePath::new(0, [EMPTY_LEAF; MERKLE_DEPTH]),
        })
    }

    /// The spent coin.
    pub fn coin(&self) -> &Coin {
        &self.coin
    }
}

/// A coin to create.
#[derive(Clone, Debug)]
pub struct OutputInfo {
    recipient: RhombusAddress,
    value: RawCoin,
    ovk: Option<OutgoingViewingKey>,
}

impl OutputInfo {
    /// A real output. Pass `ovk` so the sender can later recover the coin.
    pub fn new(recipient: RhombusAddress, value: RawCoin, ovk: Option<OutgoingViewingKey>) -> Self {
        Self {
            recipient,
            value,
            ovk,
        }
    }

    /// A zero-valued output to a random address nobody can decrypt.
    ///
    /// # Errors
    /// Fails only if key derivation fails, which has negligible probability.
    pub fn dummy(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let recipient = random_address(&SpendingKey::random(rng), rng)?;
        Ok(Self::new(recipient, RawCoin::ZERO, None))
    }

    /// The value.
    pub fn value(&self) -> RawCoin {
        self.value
    }
}

fn random_address(
    sk: &SpendingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RhombusAddress> {
    let fvk = FullViewingKey::derive(sk)?;
    RhombusAddress::derive(&fvk, Diversifier::random(rng))
}

/// Collects spends and outputs, then builds the transaction.
#[derive(Debug)]
pub struct Builder {
    anchor: Anchor,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
}

impl Builder {
    /// A builder spending against `anchor`.
    pub fn new(anchor: Anchor) -> Self {
        Self {
            anchor,
            spends: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Adds a spend.
    ///
    /// # Errors
    /// Returns [`Error::TooManyActions`] past the largest class.
    pub fn add_spend(&mut self, spend: SpendInfo) -> Result<&mut Self> {
        action_class_for(self.spends.len().saturating_add(1))?;
        self.spends.push(spend);
        Ok(self)
    }

    /// Adds an output.
    ///
    /// # Errors
    /// Returns [`Error::TooManyActions`] past the largest class.
    pub fn add_output(&mut self, output: OutputInfo) -> Result<&mut Self> {
        action_class_for(self.outputs.len().saturating_add(1))?;
        self.outputs.push(output);
        Ok(self)
    }

    fn class(&self) -> Result<usize> {
        action_class_for(self.spends.len().max(self.outputs.len()))
    }

    /// Pads, shuffles, balances including the declared fee, encrypts, signs,
    /// and proves a V2 transfer.
    ///
    /// # Errors
    /// Returns [`Error::Unbalanced`] if spends do not equal outputs, or
    /// propagates cryptographic and proving errors.
    pub fn build(
        self,
        pk: &ProvingKey,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        self.build_with_fee(RawCoin::ZERO, pk, branch, rng)
    }

    /// Builds a transfer offering the explicit public `fee` to the block
    /// producer. The fee is included in the signed transaction body.
    ///
    /// # Errors
    /// Returns [`Error::Unbalanced`] unless spends equal outputs plus fee.
    pub fn build_with_fee(
        self,
        fee: RawCoin,
        pk: &ProvingKey,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        self.build_v2_with_balance(
            fee,
            pk,
            branch,
            ValueSum::ZERO.plus(fee),
            fee.to_i64()?,
            rng,
        )
    }

    fn build_v2_with_balance(
        mut self,
        fee: RawCoin,
        pk: &ProvingKey,
        branch: BranchId,
        spent_minus_created: ValueSum,
        balance: i64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        let class = self.class()?;
        self.check_balance(spent_minus_created)?;
        self.pad(class, rng)?;
        shuffle(&mut self.spends, rng);
        shuffle(&mut self.outputs, rng);

        let prepared = self
            .spends
            .iter()
            .zip(&self.outputs)
            .map(|(spend, output)| prepare_action(spend, output, rng))
            .collect::<Result<Vec<_>>>()?;

        let bodies: Vec<&ActionBody> = prepared.iter().map(|p| &p.body).collect();
        let kind = if balance < 0 {
            COINBASE_KIND
        } else {
            TRANSFER_KIND
        };
        let sighash = sighash_of(&self.anchor, &bodies, kind, fee, branch);
        let fee_blinding =
            crypto::commitment::ValueCommitTrapdoor::sum(prepared.iter().map(|p| &p.rcv));
        let aggregate_commitment = ValueCommitment::sum(bodies.iter().map(|body| body.cv_net()));
        let net_sign = if balance < 0 {
            -crypto::pallas::Base::one()
        } else {
            crypto::pallas::Base::one()
        };
        let public = bodies
            .iter()
            .map(|body| {
                body.public_inputs(&self.anchor, *aggregate_commitment.as_point(), net_sign)
            })
            .collect::<Result<Vec<_>>>()?;
        let transaction_net = balance.unsigned_abs();
        let transaction_rcv = fee_blinding.expose();
        let witnesses: Vec<ActionWitness> = prepared
            .iter()
            .map(|p| {
                let mut witness = p.witness.clone();
                witness.transaction_net = transaction_net;
                witness.transaction_rcv = transaction_rcv;
                witness.transaction_negative = balance < 0;
                witness
            })
            .collect();
        if spent_minus_created.to_i64()? != balance {
            return Err(Error::Unbalanced);
        }
        let proof = PrivateTransactionProofV2::create(pk, &witnesses, &public, &mut *rng)?;

        let binding_key = BindingSigningKey::from_trapdoors(prepared.iter().map(|p| &p.rcv))?;
        let binding_signature = binding_key.sign(rng, &sighash);
        let actions: Vec<Action> = prepared
            .into_iter()
            .map(|p| {
                let sig = p.rsk.sign(rng, &sighash);
                p.body.sign(sig)
            })
            .collect();

        let transaction = if balance < 0 {
            Transaction::new_coinbase(self.anchor, actions, proof, binding_signature)?
        } else {
            Transaction::new(self.anchor, fee, actions, proof, binding_signature)?
        };
        Ok(transaction)
    }

    /// Builds a V2 coinbase: no spends, outputs worth exactly `credit`, the
    /// scheduled subsidy plus public transaction fees.
    ///
    /// # Errors
    /// Returns [`Error::InvalidTransaction`] if spends were added,
    /// [`Error::Unbalanced`] if outputs do not sum to `credit`, or
    /// propagates cryptographic and proving errors.
    pub fn build_coinbase(
        self,
        pk: &ProvingKey,
        credit: RawCoin,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        if !self.spends.is_empty() {
            return Err(Error::InvalidTransaction("coinbase cannot spend"));
        }
        let balance = credit
            .to_i64()?
            .checked_neg()
            .ok_or(Error::RawCoinOutOfRange)?;
        self.build_v2_with_balance(
            RawCoin::ZERO,
            pk,
            branch,
            ValueSum::ZERO.minus(credit),
            balance,
            rng,
        )
    }

    /// Spent minus created must equal the required difference.
    fn check_balance(&self, spent_minus_created: ValueSum) -> Result<()> {
        let spent = ValueSum::sum(self.spends.iter().map(|s| s.coin.value()));
        let created = ValueSum::sum(self.outputs.iter().map(|o| o.value));
        if spent.minus_sum(created) == spent_minus_created {
            Ok(())
        } else {
            Err(Error::Unbalanced)
        }
    }

    fn pad(&mut self, class: usize, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
        while self.spends.len() < class {
            self.spends.push(SpendInfo::dummy(rng)?);
        }
        while self.outputs.len() < class {
            self.outputs.push(OutputInfo::dummy(rng)?);
        }
        Ok(())
    }
}

/// An action with the secrets still needed to sign and prove it.
struct PreparedAction {
    body: ActionBody,
    rsk: RandomizedSigningKey,
    rcv: ValueCommitTrapdoor,
    witness: ActionWitness,
}

fn prepare_action(
    spend: &SpendInfo,
    output: &OutputInfo,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PreparedAction> {
    let fvk = FullViewingKey::derive(&spend.sk)?;
    let nullifier = spend.coin.nullifier(fvk.nk())?;

    let rho = Rho::from_nullifier(&nullifier)?;
    let coin = Coin::new(
        *output.recipient.diversifier(),
        *output.recipient.pk_d(),
        output.value,
        rho,
        RandomSeed::random(rng),
    );
    let cmx = coin.cmx()?;

    let rcv = ValueCommitTrapdoor::random(rng);
    let net_value = spend
        .coin
        .value()
        .to_i64()?
        .checked_sub(output.value.to_i64()?)
        .ok_or(Error::RawCoinOutOfRange)?;
    let cv_net = ValueCommitment::commit(net_value, &rcv);

    let alpha = SpendAuthRandomizer::random(rng);
    let rsk = RandomizedSigningKey::new(&SpendAuthorizingKey::derive(&spend.sk)?, &alpha)?;
    let rk = rsk.verification_key();

    let encrypted = encrypt_coin(
        &coin,
        &output.recipient.kem_key(),
        output.ovk.as_ref(),
        &cv_net,
        rng,
    )?;

    let witness = ActionWitness {
        spend: SpendWitness {
            coin: coin_witness(&spend.coin)?,
            path: spend.path.clone(),
            ak: fvk.ak().to_point()?,
            nk: fvk.nk().expose(),
            rivk: fvk.rivk().expose(),
            alpha: alpha.expose(),
        },
        output: coin_witness(&coin)?,
        rcv: rcv.expose(),
        transaction_net: 0,
        transaction_rcv: crypto::pallas::Scalar::zero(),
        transaction_negative: false,
    };
    Ok(PreparedAction {
        body: ActionBody::new(nullifier, rk, cmx, cv_net, encrypted),
        rsk,
        rcv,
        witness,
    })
}

/// The circuit's view of a coin.
fn coin_witness(coin: &Coin) -> Result<CoinWitness> {
    Ok(CoinWitness {
        g_d: coin.diversifier().base()?,
        pk_d: *coin.pk_d().as_point(),
        value: coin.value().raw(),
        rho: *coin.rho().inner(),
        psi: coin.psi(),
        rcm: coin.rseed().rcm(coin.rho()).expose(),
    })
}

/// Fisher-Yates shuffle with the caller's RNG.
fn shuffle<T>(items: &mut [T], rng: &mut (impl RngCore + CryptoRng)) {
    for i in (1..items.len()).rev() {
        let bound = u64::try_from(i.saturating_add(1)).unwrap_or(u64::MAX);
        // `bound >= 2`, so the modulo is well defined; bias is negligible
        // for the tiny lengths involved.
        #[allow(clippy::arithmetic_side_effects)]
        let j = usize::try_from(rng.next_u64() % bound).unwrap_or(0);
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use crate::address::RhombusAddress as Address;
    use crate::amount::RawCoin;
    /// The branch every test transaction is signed for.
    const BRANCH: BranchId = BranchId::new(1);

    use crypto::merkle::MerkleTree;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use transaction_circuit::PublicInputs;

    use super::*;
    use crate::encryption::{decrypt_coin_with_ivk, decrypt_coin_with_ovk};
    use crate::test_keys;
    use crate::validate;

    struct Wallet {
        sk: SpendingKey,
        fvk: FullViewingKey,
        receiver_key: crypto::encryption::ReceiverKey,
        address: Address,
    }

    fn wallet(rng: &mut ChaCha20Rng) -> Wallet {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = Address::derive(&fvk, Diversifier::random(rng)).unwrap();
        let (receiver_key, _) = fvk.receiver_key_for_diversifier(address.diversifier());
        Wallet {
            sk,
            fvk,
            receiver_key,
            address,
        }
    }

    /// A tree of coin commitments standing in for the chain.
    #[derive(Default)]
    struct Ledger {
        tree: MerkleTree,
    }

    impl Ledger {
        /// Creates a coin for `w` worth `value` and records it in the tree.
        fn fund(&mut self, rng: &mut ChaCha20Rng, w: &Wallet, value: u64) -> SpendInfo {
            let coin = Coin::new(
                *w.address.diversifier(),
                *w.address.pk_d(),
                amount(value),
                Rho::random(rng),
                RandomSeed::random(rng),
            );
            let position = self.tree.append(*coin.cmx().unwrap().inner()).unwrap();
            SpendInfo::new(w.sk.clone(), coin, self.tree.path(position).unwrap())
        }

        fn anchor(&self) -> Anchor {
            Anchor::from_base(self.tree.root())
        }
    }

    fn amount(raw: u64) -> RawCoin {
        RawCoin::from_raw(raw).unwrap()
    }

    fn verify_regular(
        tx: &Transaction,
        branch: BranchId,
        vk: &transaction_proof::VerifyingKey,
        rng: &mut ChaCha20Rng,
    ) -> Result<()> {
        validate::verify_transfer(tx, branch, vk, rng)
    }

    /// Alice pays Bob `3_000` from a `100_000` coin, keeping the change.
    fn payment(seed: u64) -> (ChaCha20Rng, Wallet, Wallet, Transaction) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (alice, bob) = (wallet(&mut rng), wallet(&mut rng));
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 100_000);
        let fee = Transaction::default_fee_for_actions(2).unwrap();
        let change = 100_000 - 3_000 - fee.raw();
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        b.add_output(OutputInfo::new(
            bob.address.clone(),
            amount(3_000),
            Some(alice.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        b.add_output(OutputInfo::new(
            alice.address.clone(),
            amount(change),
            Some(alice.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        let tx = b
            .build_with_fee(fee, test_keys::proving_key(), BRANCH, &mut rng)
            .unwrap();
        (rng, alice, bob, tx)
    }

    #[test]
    fn payment_is_padded_to_two_actions_and_fully_verifies() {
        use crate::bytes::Encodable;

        let (mut rng, _, _, tx) = payment(1);
        let digest = crypto::hash::blake2b_short(crypto::hash::PIN, &[&tx.to_vec()]);
        let digest = crypto::encoding::to_hex(&digest);
        eprintln!("transaction build vector: {digest}");
        assert_eq!(
            digest,
            "20091747c3208f26ddc1f9f1bcfea312b88cf4037541cc53aa1816b98c344c33"
        );
        assert_eq!(tx.actions().len(), 2);
        assert!(verify_regular(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_ok());
        assert!(
            matches!(
                verify_regular(&tx, BranchId::new(2), test_keys::verifying_key(), &mut rng),
                Err(Error::Crypto(crypto::Error::InvalidSignature))
            ),
            "signatures are bound to the branch they were made for"
        );
    }

    #[test]
    fn recipient_and_sender_can_decrypt_their_outputs() {
        let (_, alice, bob, tx) = payment(2);
        let bob_ivk = bob.fvk.incoming_viewing_key().unwrap();
        let alice_ovk = alice.fvk.outgoing_viewing_key();
        let mut bob_found = 0;
        let mut alice_found = Vec::new();
        for action in tx.actions() {
            let body = action.body();
            let rho = Rho::from_nullifier(body.nullifier()).unwrap();
            if let Ok(coin) = decrypt_coin_with_ivk(
                &bob_ivk,
                &bob.receiver_key,
                body.encrypted_coin(),
                rho,
                body.cmx(),
            ) {
                assert_eq!(coin.value(), amount(3_000));
                bob_found += 1;
            }
            if let Ok(coin) = decrypt_coin_with_ovk(
                &alice_ovk,
                body.encrypted_coin(),
                body.cv_net(),
                rho,
                body.cmx(),
            ) {
                alice_found.push(coin.value().raw());
            }
        }
        assert_eq!(bob_found, 1);
        alice_found.sort_unstable();
        assert_eq!(alice_found, vec![3_000, 100_000 - 3_000 - tx.fee().raw()]);
    }

    #[test]
    fn three_outputs_pad_to_four_actions_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 100_000);
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        let fee = Transaction::default_fee_for_actions(4).unwrap();
        for index in 0..3 {
            let value = if index == 2 {
                80_000 - fee.raw()
            } else {
                10_000
            };
            b.add_output(OutputInfo::new(alice.address.clone(), amount(value), None))
                .unwrap();
        }
        let tx = b
            .build_with_fee(fee, test_keys::proving_key(), BRANCH, &mut rng)
            .unwrap();
        assert_eq!(tx.actions().len(), 4);
        assert!(verify_regular(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_ok());
    }

    #[test]
    fn spending_against_the_wrong_anchor_fails_to_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 100_000);
        let mut b = Builder::new(Anchor::from_base(crypto::pallas::Base::from(99u64)));
        b.add_spend(spend).unwrap();
        let fee = Transaction::default_fee_for_actions(2).unwrap();
        b.add_output(OutputInfo::new(
            alice.address.clone(),
            amount(100_000 - fee.raw()),
            None,
        ))
        .unwrap();
        // The prover does not check constraints; the proof it emits for a
        // path that does not reach the anchor simply fails to verify.
        let tx = b
            .build_with_fee(fee, test_keys::proving_key(), BRANCH, &mut rng)
            .unwrap();
        assert_eq!(
            verify_regular(&tx, BRANCH, test_keys::verifying_key(), &mut rng),
            Err(Error::Circuit(transaction_proof::Error::InvalidProof))
        );
    }

    #[test]
    fn coinbase_creates_value_and_verifies_with_its_credit() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let miner = wallet(&mut rng);
        let credit = amount(10_000_000);
        let mut b = Builder::new(Ledger::default().anchor());
        b.add_output(OutputInfo::new(
            miner.address,
            credit,
            Some(miner.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        let tx = b
            .build_coinbase(test_keys::proving_key(), credit, BRANCH, &mut rng)
            .unwrap();
        assert_eq!(tx.actions().len(), 2);
        assert!(validate::verify_coinbase(
            &tx,
            credit,
            BRANCH,
            test_keys::verifying_key(),
            &mut rng
        )
        .is_ok());
        // Claiming a different credit, or treating it as a regular
        // transaction, fails the binding signature.
        let other = amount(1);
        assert!(validate::verify_coinbase(
            &tx,
            other,
            BRANCH,
            test_keys::verifying_key(),
            &mut rng
        )
        .is_err());
        assert!(verify_regular(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_err());
    }

    #[test]
    fn coinbase_rejects_spends_and_wrong_output_sums() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let miner = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let mut with_spend = Builder::new(ledger.anchor());
        with_spend
            .add_spend(ledger.fund(&mut rng, &miner, 5))
            .unwrap();
        assert!(matches!(
            with_spend.build_coinbase(test_keys::proving_key(), amount(5), BRANCH, &mut rng),
            Err(Error::InvalidTransaction(_))
        ));
        let mut short = Builder::new(ledger.anchor());
        short
            .add_output(OutputInfo::new(miner.address, amount(4), None))
            .unwrap();
        assert!(matches!(
            short.build_coinbase(test_keys::proving_key(), amount(5), BRANCH, &mut rng),
            Err(Error::Unbalanced)
        ));
    }

    #[test]
    fn unbalanced_transactions_are_rejected_before_proving() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 1_000);
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        b.add_output(OutputInfo::new(alice.address, amount(999), None))
            .unwrap();
        assert!(matches!(
            b.build(test_keys::proving_key(), BRANCH, &mut rng),
            Err(Error::Unbalanced)
        ));
    }

    #[test]
    fn too_many_spends_are_rejected_early() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let mut b = Builder::new(ledger.anchor());
        for _ in 0..16 {
            b.add_spend(ledger.fund(&mut rng, &alice, 1)).unwrap();
        }
        let extra = ledger.fund(&mut rng, &alice, 1);
        assert!(matches!(b.add_spend(extra), Err(Error::TooManyActions)));
        assert!(b.add_output(OutputInfo::dummy(&mut rng).unwrap()).is_ok());
    }

    #[test]
    fn dummies_have_zero_value_and_distinct_nullifiers() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let a = SpendInfo::dummy(&mut rng).unwrap();
        let b = SpendInfo::dummy(&mut rng).unwrap();
        assert_eq!(a.coin().value(), RawCoin::ZERO);
        assert_eq!(OutputInfo::dummy(&mut rng).unwrap().value(), RawCoin::ZERO);
        let nf = |s: &SpendInfo| {
            s.coin()
                .nullifier(FullViewingKey::derive(&s.sk).unwrap().nk())
                .unwrap()
        };
        assert_ne!(nf(&a), nf(&b));
    }

    #[test]
    fn witness_and_body_agree_on_public_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 500);
        let output = OutputInfo::new(alice.address, amount(200), None);
        let prepared = prepare_action(&spend, &output, &mut rng).unwrap();
        let anchor = ledger.anchor();
        let aggregate = *prepared.body.cv_net().as_point();
        let from_body = prepared
            .body
            .public_inputs(&anchor, aggregate, crypto::pallas::Base::one())
            .unwrap();
        let mut witness = prepared.witness.clone();
        witness.transaction_net = 300;
        witness.transaction_rcv = witness.rcv;
        let from_witness = PublicInputs::from_witness(*anchor.inner(), &witness).unwrap();
        assert_eq!(from_body, from_witness);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let mut items: Vec<u32> = (0..16).collect();
        shuffle(&mut items, &mut rng);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..16).collect::<Vec<_>>());
        assert_ne!(items, sorted, "shuffle left the order unchanged");
    }

    #[test]
    fn tampering_with_a_built_transaction_breaks_verification() {
        let (mut rng, _, _, tx) = payment(10);
        let mut bytes = crate::bytes::Encodable::to_vec(&tx);
        bytes[4] ^= 1; // anchor changes the sighash and the proof inputs
        let tampered = <Transaction as crate::bytes::Encodable>::from_slice(&bytes).unwrap();
        assert!(verify_regular(&tampered, BRANCH, test_keys::verifying_key(), &mut rng).is_err());
    }
}
