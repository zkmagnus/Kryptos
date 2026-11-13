//! The action circuit: all three layers of `docs/circuit.md`.
//!
//! Public inputs, one instance column, rows in this order:
//! `anchor, nf_old, rk.x, rk.y, cmx_new, cv_net.x, cv_net.y,
//!  cv_net_total.x, cv_net_total.y, net_sign`.

use crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use crypto::curve::Generator;
use crypto::merkle::{MerklePath, MERKLE_DEPTH};
use crypto::poseidon::{affine_coords, coin_commitment};
use group::Group;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};
use pasta_curves::pallas;

use crate::gadgets::coin::{
    net_witness, CoinGadgetConfig, CoinValues, CommittedCoin, COIN_ADVICES,
};
use crate::gadgets::ecc::{
    any_coords, coords, EccGadgetConfig, FullBase, ECC_ADVICES, ECC_LAGRANGE,
};
use crate::gadgets::merkle::{position_bits, MerkleConfig};
use crate::gadgets::poseidon::{self, WIDTH};
use crate::gadgets::range::check_value;
use crate::gadgets::witness::Cell;
use crate::Fp;

/// Instance rows.
pub mod rows {
    /// The anchor.
    pub const ANCHOR: usize = 0;
    /// The old nullifier.
    pub const NULLIFIER: usize = 1;
    /// `rk.x`.
    pub const RK_X: usize = 2;
    /// `rk.y`.
    pub const RK_Y: usize = 3;
    /// The new coin commitment.
    pub const CMX: usize = 4;
    /// `cv_net.x`.
    pub const CV_X: usize = 5;
    /// `cv_net.y`.
    pub const CV_Y: usize = 6;
    /// Aggregate `cv_net.x`.
    pub const NET_TOTAL_X: usize = 7;
    /// Aggregate `cv_net.y`.
    pub const NET_TOTAL_Y: usize = 8;
    /// Aggregate net sign, +1 for transfer and -1 for coinbase.
    pub const NET_SIGN: usize = 9;
    /// Number of rows.
    pub const COUNT: usize = 10;
}

/// `log2` of the number of rows the circuit needs.
pub const K: u32 = 12;

/// The plaintext of a coin as the circuit sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoinWitness {
    /// Diversified base of the recipient.
    pub g_d: pallas::Point,
    /// Transmission key of the recipient.
    pub pk_d: pallas::Point,
    /// Value in smallest units.
    pub value: u64,
    /// Uniqueness nonce.
    pub rho: Fp,
    /// Nullifier nonce.
    pub psi: Fp,
    /// Commitment trapdoor.
    pub rcm: Fp,
}

impl CoinWitness {
    /// The commitment, computed outside the circuit.
    pub fn commitment(&self) -> Fp {
        coin_commitment(
            &self.g_d, &self.pk_d, self.value, &self.rho, &self.psi, &self.rcm,
        )
    }

    fn values(coin: &Value<Self>) -> CoinValues {
        CoinValues {
            value: coin.map(|n| n.value),
            psi: coin.map(|n| n.psi),
            rcm: coin.map(|n| n.rcm),
        }
    }
}

/// Everything the prover knows about the spent coin and its owner.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    /// The spent coin.
    pub coin: CoinWitness,
    /// Its path to the anchor. Ignored by the circuit when the value is 0.
    pub path: MerklePath,
    /// The spend validating key `ak`.
    pub ak: pallas::Point,
    /// The nullifier key.
    pub nk: Fp,
    /// The ivk commitment randomness.
    pub rivk: Fp,
    /// The spend authorization randomizer.
    pub alpha: pallas::Scalar,
}

impl SpendWitness {
    /// The nullifier, computed outside the circuit.
    pub fn nullifier(&self) -> Fp {
        crypto::poseidon::nullifier(
            &self.nk,
            &self.coin.rho,
            &self.coin.psi,
            &self.coin.commitment(),
        )
    }

    /// `rk = ak + [alpha] G_spend`, computed outside the circuit.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn rk(&self) -> pallas::Point {
        self.ak + Generator::SpendAuth.point() * self.alpha
    }
}

/// The full private input of one action.
#[derive(Clone, Debug)]
pub struct ActionWitness {
    /// The spend side.
    pub spend: SpendWitness,
    /// The created coin.
    pub output: CoinWitness,
    /// The value commitment trapdoor.
    pub rcv: pallas::Scalar,
    /// Absolute net value of the whole transaction, shared by each action
    /// witness in its proof bundle.
    pub transaction_net: u64,
    /// Sum of all per-action value commitment blindings in the transaction.
    pub transaction_rcv: pallas::Scalar,
    /// Whether the aggregate transaction net is negative (coinbase).
    pub transaction_negative: bool,
}

impl ActionWitness {
    /// `cv_net`, computed outside the circuit.
    ///
    /// # Errors
    /// Returns an error if the net value does not fit `i64`, which cannot
    /// happen for values below the supply cap.
    pub fn cv_net(&self) -> Result<pallas::Point, crypto::Error> {
        let net = i128::from(self.spend.coin.value)
            .checked_sub(i128::from(self.output.value))
            .and_then(|net| i64::try_from(net).ok())
            .ok_or(crypto::Error::Internal("net value overflow"))?;
        let cv = ValueCommitment::commit(net, &ValueCommitTrapdoor::from_scalar(self.rcv));
        Ok(*cv.as_point())
    }

    /// The transaction-wide net commitment repeated by each action proof.
    pub fn transaction_cv_net(&self, negative: bool) -> Result<pallas::Point, crypto::Error> {
        let magnitude = i64::try_from(self.transaction_net)
            .map_err(|_| crypto::Error::Internal("transaction net exceeds i64"))?;
        let value = if negative {
            magnitude
                .checked_neg()
                .ok_or(crypto::Error::Internal("transaction net overflow"))?
        } else {
            magnitude
        };
        let cv = ValueCommitment::commit(
            value,
            &ValueCommitTrapdoor::from_scalar(self.transaction_rcv),
        );
        Ok(*cv.as_point())
    }
}

/// The public inputs of one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// The tree root.
    pub anchor: Fp,
    /// The nullifier of the spent coin.
    pub nf_old: Fp,
    /// The randomized verification key.
    pub rk: pallas::Point,
    /// The commitment of the created coin.
    pub cmx_new: Fp,
    /// The net value commitment.
    pub cv_net: pallas::Point,
    /// The sum of all action net value commitments.
    pub cv_net_total: pallas::Point,
    /// The sign of the aggregate net value: +1 for transfers, -1 for coinbase.
    pub net_sign: Fp,
}

impl PublicInputs {
    /// Derives the public inputs from a witness.
    ///
    /// # Errors
    /// Propagates [`ActionWitness::cv_net`] errors.
    pub fn from_witness(anchor: Fp, witness: &ActionWitness) -> Result<Self, crypto::Error> {
        Ok(Self {
            anchor,
            nf_old: witness.spend.nullifier(),
            rk: witness.spend.rk(),
            cmx_new: witness.output.commitment(),
            cv_net: witness.cv_net()?,
            cv_net_total: witness.transaction_cv_net(witness.transaction_negative)?,
            net_sign: if witness.transaction_negative {
                -Fp::one()
            } else {
                Fp::one()
            },
        })
    }

    /// The single instance column, in row order.
    pub fn to_instance(&self) -> Vec<Vec<Fp>> {
        let (rk_x, rk_y) = affine_coords(&self.rk);
        let (cv_x, cv_y) = affine_coords(&self.cv_net);
        let (net_total_x, net_total_y) = affine_coords(&self.cv_net_total);
        vec![vec![
            self.anchor,
            self.nf_old,
            rk_x,
            rk_y,
            self.cmx_new,
            cv_x,
            cv_y,
            net_total_x,
            net_total_y,
            self.net_sign,
        ]]
    }
}

/// Columns and sub-configurations.
#[derive(Clone, Debug)]
pub struct ActionConfig {
    instance: Column<Instance>,
    coin: CoinGadgetConfig,
    merkle: MerkleConfig,
    ecc: EccGadgetConfig,
}

/// The action circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionCircuit {
    witness: Value<ActionWitness>,
}

impl ActionCircuit {
    /// A circuit with a known witness, for proving.
    pub fn new(witness: ActionWitness) -> Self {
        Self {
            witness: Value::known(witness),
        }
    }

    fn spend(&self) -> Value<SpendWitness> {
        self.witness.as_ref().map(|w| w.spend.clone())
    }

    fn old_coin(&self) -> Value<CoinWitness> {
        self.witness.as_ref().map(|w| w.spend.coin)
    }

    fn new_coin(&self) -> Value<CoinWitness> {
        self.witness.as_ref().map(|w| w.output)
    }
}

impl Circuit<Fp> for ActionCircuit {
    type Config = ActionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let state: [Column<Advice>; WIDTH] = core::array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a = core::array::from_fn(|_| meta.fixed_column());
        let rc_b = core::array::from_fn(|_| meta.fixed_column());
        for column in state {
            meta.enable_equality(column);
        }
        let poseidon = poseidon::configure(meta, state, partial_sbox, rc_a, rc_b);

        let coin_advices: [Column<Advice>; COIN_ADVICES] =
            core::array::from_fn(|_| meta.advice_column());
        let coin = CoinGadgetConfig::configure(meta, coin_advices, poseidon.clone());

        let swap_advices: [Column<Advice>; 5] = core::array::from_fn(|_| meta.advice_column());
        let merkle = MerkleConfig::configure(meta, poseidon.clone(), swap_advices);

        let ecc_advices: [Column<Advice>; ECC_ADVICES] =
            core::array::from_fn(|_| meta.advice_column());
        let lagrange: [Column<Fixed>; ECC_LAGRANGE] = core::array::from_fn(|_| meta.fixed_column());
        let ecc = EccGadgetConfig::configure(meta, ecc_advices, lagrange);

        ActionConfig {
            instance,
            coin,
            merkle,
            ecc,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        config.ecc.load_table(&mut layouter)?;
        let old_coin = self.spend_side(&config, &mut layouter)?;
        let new_coin = self.output_side(&config, &mut layouter, old_coin.nf_old.clone())?;
        // 8. both values are 64-bit
        check_value(
            config.ecc.lookup(),
            layouter.namespace(|| "v_old range"),
            &old_coin.coin.value,
        )?;
        check_value(
            config.ecc.lookup(),
            layouter.namespace(|| "v_new range"),
            &new_coin.value,
        )?;
        self.value_commitment(&config, &mut layouter, &old_coin.coin, &new_coin)
    }
}

/// Cells produced by the spend side that later steps need.
struct SpendCells {
    coin: CommittedCoin,
    nf_old: Cell,
}

impl ActionCircuit {
    /// Constraints 1 to 5 and the non-identity checks of the old coin.
    fn spend_side(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<SpendCells, Error> {
        let spend = self.spend();
        let old = self.old_coin();

        let g_d_old = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "g_d_old"), old.map(|n| n.g_d))?;
        let pk_d_old = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "pk_d_old"), old.map(|n| n.pk_d))?;
        let ak = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "ak"), spend.as_ref().map(|s| s.ak))?;

        // 1. old coin commitment
        let rho_old = config.coin.load(
            layouter.namespace(|| "rho_old"),
            "rho_old",
            old.map(|n| n.rho),
        )?;
        let coin = config.coin.commit(
            layouter.namespace(|| "old coin"),
            &coords(&g_d_old).into(),
            &coords(&pk_d_old).into(),
            rho_old,
            CoinWitness::values(&old),
        )?;

        // 2. membership or dummy
        let anchor = config.coin.load_instance(
            layouter.namespace(|| "anchor"),
            config.instance,
            rows::ANCHOR,
        )?;
        let bits: [Value<bool>; MERKLE_DEPTH] = core::array::from_fn(|i| {
            spend.as_ref().map(|s| {
                position_bits(s.path.position())
                    .get(i)
                    .copied()
                    .unwrap_or(false)
            })
        });
        let siblings: [Value<Fp>; MERKLE_DEPTH] = core::array::from_fn(|i| {
            spend
                .as_ref()
                .map(|s| s.path.siblings().get(i).copied().unwrap_or(Fp::zero()))
        });
        let root = config.merkle.root(
            layouter.namespace(|| "merkle root"),
            coin.cm.clone(),
            &bits,
            &siblings,
        )?;
        config.coin.enforce_membership_or_dummy(
            layouter.namespace(|| "membership"),
            &root,
            &anchor,
            &coin.value,
        )?;

        // 3. nullifier
        let nk = config.coin.load(
            layouter.namespace(|| "nk"),
            "nk",
            spend.as_ref().map(|s| s.nk),
        )?;
        let nf_old =
            config
                .coin
                .nullifier(layouter.namespace(|| "nullifier"), nk.clone(), &coin)?;
        layouter.constrain_instance(nf_old.cell(), config.instance, rows::NULLIFIER)?;

        // 4. spend authority: pk_d_old = [ivk] g_d_old
        let rivk = config.coin.load(
            layouter.namespace(|| "rivk"),
            "rivk",
            spend.as_ref().map(|s| s.rivk),
        )?;
        let (ak_x, _) = coords(&ak);
        let ivk = config
            .coin
            .ivk(layouter.namespace(|| "ivk"), ak_x, nk, rivk)?;
        let pk_d_derived =
            config
                .ecc
                .mul_by_base(layouter.namespace(|| "[ivk] g_d"), &ivk, &g_d_old)?;
        pk_d_old.constrain_equal(layouter.namespace(|| "pk_d = [ivk] g_d"), &pk_d_derived)?;

        // 5. rk = ak + [alpha] G_spend
        let alpha_g = config.ecc.mul_fixed(
            layouter.namespace(|| "[alpha] G_spend"),
            FullBase::SpendAuth,
            spend.as_ref().map(|s| s.alpha),
        )?;
        let rk = alpha_g.add(layouter.namespace(|| "rk"), &ak)?;
        constrain_point(config, layouter, &rk, rows::RK_X, rows::RK_Y)?;

        Ok(SpendCells { coin, nf_old })
    }

    /// Constraints 6, 7 and the non-identity checks of the new coin.
    fn output_side(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
        nf_old: Cell,
    ) -> Result<CommittedCoin, Error> {
        let new = self.new_coin();
        let g_d_new = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "g_d_new"), new.map(|n| n.g_d))?;
        let pk_d_new = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "pk_d_new"), new.map(|n| n.pk_d))?;
        let coin = config.coin.commit(
            layouter.namespace(|| "new coin"),
            &coords(&g_d_new).into(),
            &coords(&pk_d_new).into(),
            nf_old,
            CoinWitness::values(&new),
        )?;
        layouter.constrain_instance(coin.cm.cell(), config.instance, rows::CMX)?;
        Ok(coin)
    }

    /// Constraint 9: `cv_net = [v_old - v_new] V + [rcv] R`.
    fn value_commitment(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
        old_coin: &CommittedCoin,
        new_coin: &CommittedCoin,
    ) -> Result<(), Error> {
        let net = self
            .witness
            .as_ref()
            .map(|w| net_witness(w.spend.coin.value, w.output.value));
        let (magnitude, sign) = config.coin.net_value(
            layouter.namespace(|| "v_old - v_new"),
            &old_coin.value,
            &new_coin.value,
            net,
        )?;
        let net_v = config
            .ecc
            .mul_value(layouter.namespace(|| "[v_net] V"), &magnitude, &sign)?;
        let rcv_r = config.ecc.mul_fixed(
            layouter.namespace(|| "[rcv] R"),
            FullBase::ValueCommitRandom,
            self.witness.as_ref().map(|w| w.rcv),
        )?;
        let expected = net_v.add(layouter.namespace(|| "[v_net] V + [rcv] R"), &rcv_r)?;
        let cv_net = config.ecc.witness_point(
            layouter.namespace(|| "cv_net"),
            self.witness
                .as_ref()
                .map(|w| w.cv_net().unwrap_or(pallas::Point::identity())),
        )?;
        cv_net.constrain_equal(layouter.namespace(|| "value balance"), &expected)?;
        constrain_point(config, layouter, &cv_net, rows::CV_X, rows::CV_Y)?;

        // The transaction aggregate is range checked once per action proof
        // instance. All instances receive the same signed value and blinding;
        // the public aggregate point is derived from the action commitments.
        let transaction_net = config.coin.load(
            layouter.namespace(|| "transaction net magnitude"),
            "transaction net magnitude",
            self.witness.as_ref().map(|w| Fp::from(w.transaction_net)),
        )?;
        let transaction_sign = config.coin.load_instance(
            layouter.namespace(|| "transaction net sign"),
            config.instance,
            rows::NET_SIGN,
        )?;
        let transaction_value = config.ecc.mul_value(
            layouter.namespace(|| "[transaction net] V"),
            &transaction_net,
            &transaction_sign,
        )?;
        let transaction_randomness = config.ecc.mul_fixed(
            layouter.namespace(|| "[transaction rcv] R"),
            FullBase::ValueCommitRandom,
            self.witness.as_ref().map(|w| w.transaction_rcv),
        )?;
        let transaction_expected = transaction_value.add(
            layouter.namespace(|| "aggregate net commitment"),
            &transaction_randomness,
        )?;
        let transaction_commitment = config.ecc.witness_point(
            layouter.namespace(|| "transaction cv_net total"),
            self.witness.as_ref().map(|w| {
                w.transaction_cv_net(w.transaction_negative)
                    .unwrap_or(pallas::Point::identity())
            }),
        )?;
        transaction_commitment.constrain_equal(
            layouter.namespace(|| "aggregate transaction balance"),
            &transaction_expected,
        )?;
        constrain_point(
            config,
            layouter,
            &transaction_commitment,
            rows::NET_TOTAL_X,
            rows::NET_TOTAL_Y,
        )
    }
}

/// Binds a point's coordinates to two instance rows.
fn constrain_point(
    config: &ActionConfig,
    layouter: &mut impl Layouter<Fp>,
    point: &crate::gadgets::ecc::AnyPoint,
    row_x: usize,
    row_y: usize,
) -> Result<(), Error> {
    let (x, y) = any_coords(point);
    layouter.constrain_instance(x.cell(), config.instance, row_x)?;
    layouter.constrain_instance(y.cell(), config.instance, row_y)
}

#[cfg(test)]
mod tests {
    use crypto::keys::{FullViewingKey, SpendingKey};
    use crypto::merkle::MerkleTree;
    use crypto::signature::{RandomizedVerificationKey, SpendAuthRandomizer};
    use ff::Field;
    use halo2_proofs::dev::{MockProver, VerifyFailure};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// A random coin owned by nobody in particular.
    fn random_coin(rng: &mut ChaCha20Rng, value: u64) -> CoinWitness {
        CoinWitness {
            g_d: pallas::Point::random(&mut *rng),
            pk_d: pallas::Point::random(&mut *rng),
            value,
            rho: Fp::random(&mut *rng),
            psi: Fp::random(&mut *rng),
            rcm: Fp::random(&mut *rng),
        }
    }

    struct Fixture {
        witness: ActionWitness,
        public: PublicInputs,
    }

    /// A real spend by a real key of a coin in a tree with other leaves.
    fn fixture(seed: u64, value: u64) -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let d = crypto::keys::Diversifier::random(&mut rng);
        let g_d = d.base().unwrap();
        let pk_d = *ivk.transmission_key(&d).unwrap().as_point();
        let coin = CoinWitness {
            g_d,
            pk_d,
            value,
            rho: Fp::random(&mut rng),
            psi: Fp::random(&mut rng),
            rcm: Fp::random(&mut rng),
        };

        let mut tree = MerkleTree::new();
        tree.append(Fp::random(&mut rng)).unwrap();
        let position = tree.append(coin.commitment()).unwrap();
        tree.append(Fp::random(&mut rng)).unwrap();

        let spend = SpendWitness {
            coin,
            path: tree.path(position).unwrap(),
            ak: fvk.ak().to_point().unwrap(),
            nk: fvk.nk().expose(),
            rivk: fvk.rivk().expose(),
            alpha: pallas::Scalar::random(&mut rng),
        };
        let mut output = random_coin(&mut rng, value.min(5));
        output.rho = spend.nullifier();
        let rcv = pallas::Scalar::random(&mut rng);
        let transaction_net = value - output.value;
        let witness = ActionWitness {
            spend,
            output,
            rcv,
            transaction_net,
            transaction_rcv: rcv,
            transaction_negative: false,
        };
        let public = PublicInputs::from_witness(tree.root(), &witness).unwrap();
        Fixture { witness, public }
    }

    fn prove(f: &Fixture, public: &PublicInputs) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ActionCircuit::new(f.witness.clone());
        MockProver::run(K, &circuit, public.to_instance())
            .unwrap()
            .verify()
    }

    fn fails(f: &Fixture, public: &PublicInputs) -> bool {
        let circuit = ActionCircuit::new(f.witness.clone());
        MockProver::run(K, &circuit, public.to_instance()).map_or(true, |p| p.verify().is_err())
    }

    #[test]
    fn instance_has_the_documented_row_count() {
        assert_eq!(fixture(1, 10).public.to_instance()[0].len(), rows::COUNT);
    }

    #[test]
    fn rk_matches_reddsa_randomization() {
        let f = fixture(2, 10);
        let fvk_ak = crypto::keys::SpendValidatingKey::from_bytes(
            &crypto::encoding::point_to_bytes(&f.witness.spend.ak),
        )
        .unwrap();
        let alpha = SpendAuthRandomizer::from_scalar(f.witness.spend.alpha);
        let rk = RandomizedVerificationKey::new(&fvk_ak, &alpha);
        assert_eq!(
            rk.to_bytes(),
            crypto::encoding::point_to_bytes(&f.public.rk)
        );
    }

    #[test]
    fn valid_spend_satisfies_the_circuit() {
        let f = fixture(3, 1_000);
        assert_eq!(prove(&f, &f.public), Ok(()));
    }

    #[test]
    fn dummy_spend_accepts_any_anchor() {
        let f = fixture(4, 0);
        let public = PublicInputs {
            anchor: Fp::from(7),
            ..f.public
        };
        assert_eq!(prove(&f, &public), Ok(()));
    }

    #[test]
    fn wrong_anchor_fails_for_a_real_spend() {
        let f = fixture(5, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                anchor: Fp::from(7),
                ..f.public
            }
        ));
    }

    #[test]
    fn wrong_nullifier_fails() {
        let f = fixture(6, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                nf_old: f.public.nf_old + Fp::one(),
                ..f.public
            }
        ));
    }

    #[test]
    fn wrong_nullifier_key_breaks_spend_authority() {
        let mut f = fixture(7, 1_000);
        f.witness.spend.nk += Fp::one();
        // nk feeds both the nullifier and ivk; recompute the public nullifier
        // so only the spend authority constraint can fail.
        let public = PublicInputs {
            nf_old: f.witness.spend.nullifier(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_rivk_breaks_spend_authority() {
        let mut f = fixture(8, 1_000);
        f.witness.spend.rivk += Fp::one();
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn foreign_ak_breaks_spend_authority_and_rk() {
        let mut f = fixture(9, 1_000);
        f.witness.spend.ak = pallas::Point::random(ChaCha20Rng::seed_from_u64(99));
        let public = PublicInputs {
            rk: f.witness.spend.rk(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_rk_fails() {
        let f = fixture(10, 1_000);
        let public = PublicInputs {
            rk: pallas::Point::random(ChaCha20Rng::seed_from_u64(98)),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_new_commitment_fails() {
        let f = fixture(11, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                cmx_new: f.public.cmx_new + Fp::one(),
                ..f.public
            }
        ));
    }

    #[test]
    fn new_coin_must_chain_from_the_old_nullifier() {
        let mut f = fixture(12, 1_000);
        f.witness.output.rho += Fp::one();
        let public = PublicInputs {
            cmx_new: f.witness.output.commitment(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn tampered_path_fails_for_a_real_spend() {
        let mut f = fixture(13, 1_000);
        let mut siblings = *f.witness.spend.path.siblings();
        siblings[3] += Fp::one();
        f.witness.spend.path = MerklePath::new(f.witness.spend.path.position(), siblings);
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn wrong_value_commitment_fails() {
        let f = fixture(14, 1_000);
        let public = PublicInputs {
            cv_net: pallas::Point::random(ChaCha20Rng::seed_from_u64(97)),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn value_commitment_binds_the_values() {
        let mut f = fixture(15, 1_000);
        // Claim a different net value in cv_net than the coins carry.
        let forged = ValueCommitment::commit(
            1_000 - 5 + 1,
            &ValueCommitTrapdoor::from_scalar(f.witness.rcv),
        );
        let public = PublicInputs {
            cv_net: *forged.as_point(),
            ..f.public
        };
        assert!(fails(&f, &public));
        f.witness.rcv += pallas::Scalar::one();
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn identity_points_are_rejected() {
        let mut f = fixture(16, 1_000);
        f.witness.output.g_d = pallas::Point::identity();
        let public = PublicInputs {
            cmx_new: f.witness.output.commitment(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn cv_net_matches_value_commitment_of_the_difference() {
        let f = fixture(17, 1_000);
        let expected =
            ValueCommitment::commit(995, &ValueCommitTrapdoor::from_scalar(f.witness.rcv));
        assert_eq!(f.public.cv_net, *expected.as_point());
    }

    #[test]
    fn value_commitment_handles_every_sign_of_the_net_value() {
        // Spend more than created, less than created, and the same.
        for (seed, old, new) in [(18u64, 1_000u64, 5u64), (19, 1_000, 2_000), (20, 7, 7)] {
            let mut f = fixture(seed, old);
            f.witness.output.value = new;
            f.witness.transaction_net = old.abs_diff(new);
            f.witness.transaction_negative = new > old;
            f.witness.transaction_rcv = f.witness.rcv;
            let public = PublicInputs::from_witness(f.public.anchor, &f.witness).unwrap();
            assert_eq!(prove(&f, &public), Ok(()), "old {old} new {new}");
        }
    }

    #[test]
    fn net_value_witness_is_the_signed_difference() {
        assert_eq!(net_witness(10, 3), (7, false));
        assert_eq!(net_witness(3, 10), (7, true));
        assert_eq!(net_witness(4, 4), (0, false));
        assert_eq!(net_witness(0, u64::MAX), (u64::MAX, true));
    }
}
