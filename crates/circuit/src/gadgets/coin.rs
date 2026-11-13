//! Coin gadgets: commitment, nullifier and the membership-or-dummy gate.

#![allow(clippy::arithmetic_side_effects)] // gate expressions are symbolic

use crypto::poseidon::{COIN_COMMIT_INPUTS, IVK_INPUTS, NULLIFIER_INPUTS};
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Error, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

use super::poseidon::{self, PoseidonConfig};
use super::witness::{load, Cell};
use crate::Fp;

/// Number of advice columns the coin gadget needs.
pub const COIN_ADVICES: usize = 3;

/// Coordinate cells of a point already constrained elsewhere.
#[derive(Clone, Debug)]
pub struct PointCells {
    /// x-coordinate.
    pub x: Cell,
    /// y-coordinate.
    pub y: Cell,
}

impl From<(Cell, Cell)> for PointCells {
    fn from((x, y): (Cell, Cell)) -> Self {
        Self { x, y }
    }
}

/// The cells a coin commitment produces.
#[derive(Clone, Debug)]
pub struct CommittedCoin {
    /// The commitment.
    pub cm: Cell,
    /// The value, for the membership gate and the value commitment.
    pub value: Cell,
    /// `rho`, for the nullifier.
    pub rho: Cell,
    /// `psi`, for the nullifier.
    pub psi: Cell,
}

/// Plaintext fields of a coin as `Value`s.
#[derive(Clone, Copy, Debug)]
pub struct CoinValues {
    /// Value in smallest units.
    pub value: Value<u64>,
    /// Nullifier nonce.
    pub psi: Value<Fp>,
    /// Commitment trapdoor.
    pub rcm: Value<Fp>,
}

/// Columns and selectors of the coin gadget.
#[derive(Clone, Debug)]
pub struct CoinGadgetConfig {
    advices: [Column<Advice>; COIN_ADVICES],
    poseidon: PoseidonConfig,
    q_member: Selector,
    q_net: Selector,
}

/// The signed difference of two 64-bit values as the value base's scalar
/// wants it: magnitude and whether it is negative.
#[must_use]
pub fn net_witness(old: u64, new: u64) -> (u64, bool) {
    (old.abs_diff(new), new > old)
}

impl CoinGadgetConfig {
    /// Configures the membership gate on `advices` and keeps the Poseidon
    /// configuration for hashing.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advices: [Column<Advice>; COIN_ADVICES],
        poseidon: PoseidonConfig,
    ) -> Self {
        for column in advices {
            meta.enable_equality(column);
        }
        let q_member = meta.selector();
        meta.create_gate("membership or dummy", |meta| {
            let q = meta.query_selector(q_member);
            let root = meta.query_advice(advices[0], Rotation::cur());
            let anchor = meta.query_advice(advices[1], Rotation::cur());
            let value = meta.query_advice(advices[2], Rotation::cur());
            Constraints::with_selector(q, [("(root - anchor) * value", (root - anchor) * value)])
        });
        let q_net = meta.selector();
        meta.create_gate("net value", |meta| {
            let q = meta.query_selector(q_net);
            let old = meta.query_advice(advices[0], Rotation::cur());
            let new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[0], Rotation::next());
            Constraints::with_selector(
                q,
                [("old - new - magnitude * sign", old - new - magnitude * sign)],
            )
        });
        Self {
            advices,
            poseidon,
            q_member,
            q_net,
        }
    }

    /// Loads a field element into a fresh cell.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn load(
        &self,
        layouter: impl Layouter<Fp>,
        name: &'static str,
        value: Value<Fp>,
    ) -> Result<Cell, Error> {
        load(layouter, self.advices[0], name, value)
    }

    /// Copies instance row `row` into a fresh cell.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn load_instance(
        &self,
        mut layouter: impl Layouter<Fp>,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<Cell, Error> {
        layouter.assign_region(
            || "instance copy",
            |mut region| {
                region.assign_advice_from_instance(|| "instance", instance, row, self.advices[0], 0)
            },
        )
    }

    /// Commits to a coin whose `rho` is an existing cell.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn commit(
        &self,
        mut layouter: impl Layouter<Fp>,
        g_d: &PointCells,
        pk_d: &PointCells,
        rho: Cell,
        coin: CoinValues,
    ) -> Result<CommittedCoin, Error> {
        let value = self.load(
            layouter.namespace(|| "value"),
            "value",
            coin.value.map(Fp::from),
        )?;
        let psi = self.load(layouter.namespace(|| "psi"), "psi", coin.psi)?;
        let rcm = self.load(layouter.namespace(|| "rcm"), "rcm", coin.rcm)?;
        let cm = poseidon::hash::<COIN_COMMIT_INPUTS>(
            &self.poseidon,
            layouter.namespace(|| "coin commitment"),
            [
                g_d.x.clone(),
                g_d.y.clone(),
                pk_d.x.clone(),
                pk_d.y.clone(),
                value.clone(),
                rho.clone(),
                psi.clone(),
                rcm,
            ],
        )?;
        Ok(CommittedCoin {
            cm,
            value,
            rho,
            psi,
        })
    }

    /// `Poseidon(nk, rho, psi, cm)`.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn nullifier(
        &self,
        layouter: impl Layouter<Fp>,
        nk: Cell,
        coin: &CommittedCoin,
    ) -> Result<Cell, Error> {
        poseidon::hash::<NULLIFIER_INPUTS>(
            &self.poseidon,
            layouter,
            [nk, coin.rho.clone(), coin.psi.clone(), coin.cm.clone()],
        )
    }

    /// `Poseidon(ak.x, nk, rivk)`, the incoming viewing key before reduction.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn ivk(
        &self,
        layouter: impl Layouter<Fp>,
        ak_x: Cell,
        nk: Cell,
        rivk: Cell,
    ) -> Result<Cell, Error> {
        poseidon::hash::<IVK_INPUTS>(&self.poseidon, layouter, [ak_x, nk, rivk])
    }

    /// Witnesses `old - new` as a magnitude and a sign, enforcing
    /// `old - new = magnitude * sign`. With both values below `2^64` and
    /// the magnitude range-checked by the value base multiplication, the
    /// equation holds over the integers.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn net_value(
        &self,
        mut layouter: impl Layouter<Fp>,
        old: &Cell,
        new: &Cell,
        net: Value<(u64, bool)>,
    ) -> Result<(Cell, Cell), Error> {
        layouter.assign_region(
            || "net value",
            |mut region| {
                self.q_net.enable(&mut region, 0)?;
                old.copy_advice(|| "old", &mut region, self.advices[0], 0)?;
                new.copy_advice(|| "new", &mut region, self.advices[1], 0)?;
                let magnitude = region.assign_advice(
                    || "magnitude",
                    self.advices[2],
                    0,
                    || net.map(|(magnitude, _)| Fp::from(magnitude)),
                )?;
                let sign = region.assign_advice(
                    || "sign",
                    self.advices[0],
                    1,
                    || net.map(|(_, negative)| if negative { -Fp::one() } else { Fp::one() }),
                )?;
                Ok((magnitude, sign))
            },
        )
    }

    /// Enforces `(root - anchor) * value = 0`.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn enforce_membership_or_dummy(
        &self,
        mut layouter: impl Layouter<Fp>,
        root: &Cell,
        anchor: &Cell,
        value: &Cell,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "membership or dummy",
            |mut region| {
                self.q_member.enable(&mut region, 0)?;
                root.copy_advice(|| "root", &mut region, self.advices[0], 0)?;
                anchor.copy_advice(|| "anchor", &mut region, self.advices[1], 0)?;
                value.copy_advice(|| "value", &mut region, self.advices[2], 0)?;
                Ok(())
            },
        )
    }
}
