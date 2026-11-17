//! Fixed generators, hash-to-curve and Pedersen helpers on Pallas.
//!
//! All generators are derived by hashing a domain string to the curve, so
//! nobody knows a discrete-log relation between any two of them.

use std::sync::LazyLock;

use ff::{Field, PrimeField};
use group::{Curve, Group};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use reddsa::orchard::{Binding, SpendAuth};
use reddsa::{SigType, SigningKey, VerificationKey};

use crate::encoding::{base_from_bytes, point_from_bytes};
use crate::hash::WIDE_OUTPUT_LEN;

/// Hash-to-curve domain prefix shared by every generator in the system.
const GENERATOR_DOMAIN: &str = "rhombus:Generator";
/// Hash-to-curve domain for diversified bases `g_d`.
const DIVERSIFIED_BASE_DOMAIN: &str = "rhombus:DiversifiedBase";

/// Names of the fixed generators. Each maps to an independent point.
///
/// Two of them are not ours: [`Generator::SpendAuth`] and
/// [`Generator::ValueCommitRandom`] are the `RedPallas` basepoints fixed by the
/// `reddsa` crate, because spend authorization keys and binding signatures
/// must live on those bases for the audited signature code to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generator {
    /// Value base `V` of the value commitment.
    ValueCommitValue,
    /// Randomness base `R` of the value commitment, equal to the `RedPallas`
    /// binding signature basepoint.
    ValueCommitRandom,
    /// Base of spend authorization keys `ak = [ask] G_spend`, equal to the
    /// `RedPallas` spend authorization basepoint.
    SpendAuth,
}

impl Generator {
    /// Every generator, in table order.
    pub const ALL: [Self; 3] = [
        Self::ValueCommitValue,
        Self::ValueCommitRandom,
        Self::SpendAuth,
    ];

    fn derive(self) -> pallas::Point {
        match self {
            Self::ValueCommitValue => hash_to_point(GENERATOR_DOMAIN, b"value-commit-v"),
            Self::ValueCommitRandom => reddsa_basepoint::<Binding>(),
            Self::SpendAuth => reddsa_basepoint::<SpendAuth>(),
        }
    }

    /// The generator point. Computed once and cached.
    pub fn point(self) -> pallas::Point {
        static TABLE: LazyLock<[pallas::Point; 3]> =
            LazyLock::new(|| Generator::ALL.map(Generator::derive));
        // `ALL` has exactly one entry per variant, in enum order.
        #[allow(clippy::indexing_slicing)]
        TABLE[self as usize]
    }
}

/// Recovers a `RedPallas` basepoint from `reddsa`, which keeps it private, by
/// asking for the verification key of the signing key `1`.
fn reddsa_basepoint<T: SigType>() -> pallas::Point {
    let one = pallas::Scalar::ONE.to_repr();
    // Both steps only fail on invalid input; `1` is a valid non-zero scalar
    // and its verification key is a valid point. Tested below.
    #[allow(clippy::expect_used)]
    let key = SigningKey::<T>::try_from(one).expect("scalar one is a valid signing key");
    let bytes: [u8; 32] = VerificationKey::from(&key).into();
    #[allow(clippy::expect_used)]
    point_from_bytes(&bytes).expect("basepoint is a valid point")
}

/// Hashes `message` to a curve point under `domain` using simplified SWU.
pub fn hash_to_point(domain: &str, message: &[u8]) -> pallas::Point {
    pallas::Point::hash_to_curve(domain)(message)
}

/// The diversified base `g_d` for a diversifier, or the identity if the
/// diversifier is invalid. Callers must reject the identity.
pub fn diversified_base(diversifier: &[u8]) -> pallas::Point {
    hash_to_point(DIVERSIFIED_BASE_DOMAIN, diversifier)
}

/// `ExtractP`: the affine x-coordinate of a point, or zero for the identity.
pub fn extract_x(point: &pallas::Point) -> pallas::Base {
    let affine = point.to_affine();
    affine
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or(pallas::Base::ZERO)
}

/// Embeds a base field element into the scalar field without changing its value.
///
/// The Pallas base field modulus is smaller than the scalar field modulus,
/// so every canonical base field element has an exact scalar representation.
pub fn base_to_scalar(value: &pallas::Base) -> pallas::Scalar {
    let mut wide = [0u8; WIDE_OUTPUT_LEN];
    let repr = value.to_repr();
    // The first 32 bytes of the 64-byte buffer are the canonical encoding.
    #[allow(clippy::indexing_slicing)]
    wide[..repr.len()].copy_from_slice(&repr);
    crate::hash::wide_to_scalar(&wide)
}

/// Converts a scalar to the same integer in the base field, if it fits.
///
/// The scalar field modulus is larger than the base field modulus. This
/// conversion rejects out-of-range values rather than reducing them;
/// [`base_to_scalar`] inverts every successful conversion.
///
/// # Errors
/// Returns [`crate::Error::InvalidBase`] if `value` is at least the base field
/// modulus.
pub fn scalar_to_base(value: &pallas::Scalar) -> crate::Result<pallas::Base> {
    base_from_bytes(&value.to_repr())
}

/// A Pedersen commitment `[value] * value_base + [blind] * blind_base`.
#[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
pub fn pedersen(
    value: &pallas::Scalar,
    blind: &pallas::Scalar,
    value_base: Generator,
    blind_base: Generator,
) -> pallas::Point {
    value_base.point() * value + blind_base.point() * blind
}

/// Whether a point is the group identity.
pub fn is_identity(point: &pallas::Point) -> bool {
    bool::from(point.is_identity())
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    const ALL: [Generator; 3] = Generator::ALL;

    #[test]
    fn generators_are_distinct_and_not_identity() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(!is_identity(&a.point()), "{a:?} is the identity");
            for b in ALL.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.point(), b.point(), "{a:?} == {b:?}");
            }
        }
    }

    #[test]
    fn table_order_matches_enum_discriminants() {
        for (index, g) in ALL.iter().enumerate() {
            assert_eq!(*g as usize, index);
            assert_eq!(g.point(), g.derive());
        }
    }

    #[test]
    fn reddsa_basepoints_match_signing_key_one() {
        // [1] B == B, so the verification key of `1` encodes the basepoint.
        let one = pallas::Scalar::ONE.to_repr();
        let key = SigningKey::<Binding>::try_from(one).unwrap();
        let bytes: [u8; 32] = VerificationKey::from(&key).into();
        assert_eq!(
            point_from_bytes(&bytes).unwrap(),
            Generator::ValueCommitRandom.point()
        );
    }

    #[test]
    fn generators_are_stable_across_calls() {
        assert_eq!(Generator::SpendAuth.point(), Generator::SpendAuth.point());
    }

    #[test]
    fn hash_to_point_separates_domains_and_messages() {
        assert_ne!(hash_to_point("a", b"m"), hash_to_point("b", b"m"));
        assert_ne!(hash_to_point("a", b"m"), hash_to_point("a", b"n"));
    }

    #[test]
    fn extract_x_of_identity_is_zero() {
        assert_eq!(extract_x(&pallas::Point::identity()), pallas::Base::ZERO);
    }

    #[test]
    fn extract_x_ignores_sign() {
        let point = pallas::Point::random(ChaCha20Rng::seed_from_u64(3));
        assert_eq!(extract_x(&point), extract_x(&-point));
    }

    #[test]
    fn base_to_scalar_is_identity_on_small_values() {
        let small = pallas::Base::from(123_456_789u64);
        assert_eq!(base_to_scalar(&small), pallas::Scalar::from(123_456_789u64));
    }

    #[test]
    fn field_conversions_round_trip_values_that_fit_in_both_fields() {
        for base in [
            pallas::Base::ZERO,
            pallas::Base::ONE,
            pallas::Base::from(42u64),
            -pallas::Base::ONE,
        ] {
            let scalar = pallas::Scalar::from_repr(base.to_repr()).unwrap();
            assert_eq!(base_to_scalar(&base), scalar);
            assert_eq!(scalar_to_base(&scalar), Ok(base));
        }
    }

    #[test]
    fn scalar_to_base_rejects_the_modulus_boundary_and_larger_values() {
        let largest_base = -pallas::Base::ONE;
        let base_modulus =
            pallas::Scalar::from_repr(largest_base.to_repr()).unwrap() + pallas::Scalar::ONE;
        for scalar in [
            base_modulus,
            base_modulus + pallas::Scalar::ONE,
            -pallas::Scalar::ONE,
        ] {
            assert_eq!(scalar_to_base(&scalar), Err(crate::Error::InvalidBase));
        }
    }

    #[test]
    fn pedersen_is_additively_homomorphic() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (v1, v2) = (
            pallas::Scalar::random(&mut rng),
            pallas::Scalar::random(&mut rng),
        );
        let (r1, r2) = (
            pallas::Scalar::random(&mut rng),
            pallas::Scalar::random(&mut rng),
        );
        let (vb, rb) = (Generator::ValueCommitValue, Generator::ValueCommitRandom);
        let sum = pedersen(&v1, &r1, vb, rb) + pedersen(&v2, &r2, vb, rb);
        assert_eq!(sum, pedersen(&(v1 + v2), &(r1 + r2), vb, rb));
    }

    #[test]
    fn pedersen_with_zero_blinding_is_a_plain_multiple() {
        let v = pallas::Scalar::from(9u64);
        let got = pedersen(
            &v,
            &pallas::Scalar::ZERO,
            Generator::ValueCommitValue,
            Generator::ValueCommitRandom,
        );
        assert_eq!(got, Generator::ValueCommitValue.point() * v);
    }
}
