//! Difficulty targets in compact form, and the work a target represents.
//!
//! The compact form is Bitcoin's: one exponent byte and a 23-bit mantissa.
//! A header's hash, read as a big-endian 256-bit number, must not exceed
//! the target. Work is `2^256 / (target + 1)`, so halving the target
//! doubles the work, and chains compare by summed work.

// Shifts and divisions on `U256` here are bounded by explicit checks on the
// exponent and the mantissa, and division never sees a zero denominator.
#![allow(clippy::arithmetic_side_effects)]

use crate::Error;
use protocol::block::BlockHash;

mod u256 {
    // Generated arithmetic; newer compilers deprecate the `max_value` the
    // macro expands to.
    #![allow(missing_docs, deprecated, clippy::all, clippy::pedantic)]
    uint::construct_uint! {
        /// A 256-bit unsigned integer.
        pub struct U256(4);
    }
}
pub use u256::U256;

/// Cumulative, validated proof of work. Arithmetic never wraps or saturates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainWork(U256);

impl ChainWork {
    /// Genesis contributes no work: it is a fixed, unmined network anchor.
    pub const ZERO: Self = Self(U256::zero());
    /// Largest representable cumulative work.
    pub const MAX: Self = Self(U256::MAX);

    /// Wraps an integer, for persisted work and node policy thresholds.
    pub const fn from_u256(value: U256) -> Self {
        Self(value)
    }

    /// The underlying integer, for non-consensus reporting.
    pub fn as_u256(self) -> U256 {
        self.0
    }

    /// Decodes the fixed-width big-endian database representation.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(U256::from_big_endian(&bytes))
    }

    /// Encodes the fixed-width big-endian database representation.
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_big_endian()
    }

    /// Adds validated work without wrapping.
    ///
    /// # Errors
    /// Returns [`Error::ChainWorkOverflow`] if the sum exceeds 256 bits.
    pub fn checked_add(self, work: Self) -> Result<Self, Error> {
        self.0
            .checked_add(work.0)
            .map(Self)
            .ok_or(Error::ChainWorkOverflow)
    }
}

/// A difficulty target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target(U256);

/// Mantissa bits in the compact form.
const MANTISSA_BITS: u32 = 23;
/// Mask of the mantissa.
const MANTISSA_MASK: u32 = (1 << MANTISSA_BITS) - 1;
/// The sign bit, which is never allowed.
const SIGN_BIT: u32 = 1 << MANTISSA_BITS;

impl Target {
    /// The largest possible target, met by every hash.
    pub const MAX: Self = Self(U256::MAX);

    /// Wraps a 256-bit value.
    pub fn from_u256(value: U256) -> Self {
        Self(value)
    }

    /// The 256-bit value.
    pub fn as_u256(&self) -> U256 {
        self.0
    }

    /// Decodes the compact form.
    ///
    /// # Errors
    /// Returns [`Error::InvalidTarget`] for a zero, negative or overflowing
    /// encoding.
    pub fn from_compact(compact: u32) -> Result<Self, Error> {
        let exponent = compact >> 24;
        let mantissa = compact & MANTISSA_MASK;
        if compact & SIGN_BIT != 0 || mantissa == 0 {
            return Err(Error::InvalidTarget);
        }
        let value = if exponent <= 3 {
            U256::from(mantissa >> (8 * (3 - exponent)))
        } else {
            let shift = 8 * (exponent - 3);
            if shift >= 256 || (U256::from(mantissa) << shift) >> shift != U256::from(mantissa) {
                return Err(Error::InvalidTarget);
            }
            U256::from(mantissa) << shift
        };
        if value.is_zero() {
            return Err(Error::InvalidTarget);
        }
        Ok(Self(value))
    }

    /// Encodes to the compact form, rounding down like Bitcoin does.
    pub fn to_compact(&self) -> u32 {
        // `bits()` is at most 256, so the conversion cannot truncate.
        let mut exponent = u32::try_from(self.0.bits()).unwrap_or(256).div_ceil(8);
        let mut mantissa = if exponent <= 3 {
            (self.0 << (8 * (3 - exponent))).low_u32()
        } else {
            (self.0 >> (8 * (exponent - 3))).low_u32()
        };
        if mantissa & SIGN_BIT != 0 {
            mantissa >>= 8;
            exponent = exponent.saturating_add(1);
        }
        (exponent << 24) | mantissa
    }

    /// Whether `hash` meets this target.
    pub fn is_met_by(&self, hash: &BlockHash) -> bool {
        U256::from_big_endian(hash.as_bytes()) <= self.0
    }

    /// Whether a 32-byte proof hash meets this target, interpreted big-endian.
    pub fn is_met_by_hash(&self, hash: &[u8; 32]) -> bool {
        U256::from_big_endian(hash) <= self.0
    }

    /// The work this validated target represents, `floor(2^256 / (target + 1))`.
    ///
    /// # Errors
    /// A zero target is invalid: its work would be 2^256, which cannot fit.
    pub fn work(&self) -> Result<ChainWork, Error> {
        if self.0.is_zero() {
            return Err(Error::InvalidTarget);
        }
        // MAX + 1 cannot fit, but its work is exactly one.
        let Some(denominator) = self.0.checked_add(U256::one()) else {
            return Ok(ChainWork::from_u256(U256::one()));
        };
        let work = (!self.0 / denominator)
            .checked_add(U256::one())
            .ok_or(Error::ChainWorkOverflow)?;
        Ok(ChainWork::from_u256(work))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_boundaries_and_checked_accumulation() {
        assert!(matches!(
            Target::from_u256(U256::zero()).work(),
            Err(Error::InvalidTarget)
        ));
        let one = Target::MAX.work().unwrap();
        assert_eq!(one.as_u256(), U256::one());
        assert_eq!(
            Target::from_u256(U256::one()).work().unwrap().as_u256(),
            U256::one() << 255
        );
        let mut total = ChainWork::ZERO;
        for _ in 0..100 {
            let next = total.checked_add(one).unwrap();
            assert!(next > total);
            assert_eq!(ChainWork::from_be_bytes(next.to_be_bytes()), next);
            total = next;
        }
        assert!(matches!(
            ChainWork::MAX.checked_add(one),
            Err(Error::ChainWorkOverflow)
        ));
        let half = Target::from_u256(U256::one()).work().unwrap();
        assert!(matches!(
            half.checked_add(half),
            Err(Error::ChainWorkOverflow)
        ));
    }

    #[test]
    fn compact_roundtrips_known_values() {
        for compact in [
            0x1d00_ffffu32,
            0x1b04_86b6,
            0x2007_ffff,
            0x1f07_ffff,
            0x0300_ffff,
        ] {
            let target = Target::from_compact(compact).unwrap();
            assert_eq!(target.to_compact(), compact, "{compact:#x}");
        }
    }

    #[test]
    fn bitcoin_genesis_target_decodes_as_expected() {
        let target = Target::from_compact(0x1d00_ffff).unwrap();
        assert_eq!(target.as_u256(), U256::from(0xffffu64) << 208);
    }

    #[test]
    fn invalid_compact_forms_are_rejected() {
        assert!(matches!(Target::from_compact(0), Err(Error::InvalidTarget)));
        assert!(
            matches!(Target::from_compact(0x0180_0000), Err(Error::InvalidTarget)),
            "sign bit"
        );
        assert!(
            matches!(Target::from_compact(0xff00_0001), Err(Error::InvalidTarget)),
            "overflow"
        );
    }

    #[test]
    fn hash_comparison_is_big_endian() {
        let target = Target::from_u256(U256::from(0x0100u64) << 240);
        assert!(target.is_met_by(&BlockHash::from_bytes([0; 32])));
        let mut equal = [0u8; 32];
        equal[0] = 0x01;
        assert!(target.is_met_by(&BlockHash::from_bytes(equal)));
        let mut above = equal;
        above[31] = 1;
        assert!(!target.is_met_by(&BlockHash::from_bytes(above)));
    }

    #[test]
    fn halving_the_target_doubles_the_work() {
        let easy = Target::from_u256(U256::one() << 200);
        let hard = Target::from_u256(U256::one() << 199);
        // 2^256 / (2^199 + 1) floors to 2^57 - 1, twice 2^56 - 1 plus one.
        assert_eq!(
            hard.work().unwrap().as_u256(),
            easy.work().unwrap().as_u256() * 2 + 1
        );
        assert_eq!(Target::MAX.work().unwrap().as_u256(), U256::one());
    }
}
