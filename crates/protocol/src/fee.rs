//! Private fee openings carried as transaction-relay metadata, not on-chain.

use crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use crypto::encoding::{scalar_from_bytes, scalar_to_bytes};
use crypto::pallas;

use crate::bytes::{Encodable, Reader, Writer};
use crate::coin::Rhombus;
use crate::{Error, Result};

/// Encoded length of a fee opening: raw amount plus Pedersen blinding scalar.
pub const FEE_OPENING_LEN: usize = 8 + crypto::encoding::ENCODED_LEN;

/// A fee amount and the blinding needed to open the transaction's aggregate
/// `cv_net` commitment. This is relay metadata; it must never be put in a
/// transaction or block encoding.
#[derive(Clone, Debug)]
pub struct FeeOpening {
    fee: Rhombus,
    blinding: ValueCommitTrapdoor,
}

impl PartialEq for FeeOpening {
    fn eq(&self, other: &Self) -> bool {
        self.fee == other.fee && self.blinding.expose() == other.blinding.expose()
    }
}

impl Eq for FeeOpening {}

impl FeeOpening {
    /// Creates an opening from the fee and aggregate commitment blinding.
    pub fn new(fee: Rhombus, blinding: ValueCommitTrapdoor) -> Self {
        Self { fee, blinding }
    }

    /// The opened fee amount.
    pub fn fee(&self) -> Rhombus {
        self.fee
    }

    /// The scalar blinding, for the block producer's aggregate binding key.
    pub fn blinding(&self) -> pallas::Scalar {
        self.blinding.expose()
    }

    /// Checks that this opening matches the transaction's action commitments.
    ///
    /// # Errors
    /// Returns an error when the amount cannot be committed as a signed value
    /// or when the opening does not match the commitments.
    pub fn verify<'a>(
        &self,
        commitments: impl IntoIterator<Item = &'a ValueCommitment>,
    ) -> Result<()> {
        let fee = self.fee.to_i64()?;
        let opened = ValueCommitment::commit(fee, &self.blinding);
        if ValueCommitment::sum(commitments) == opened {
            Ok(())
        } else {
            Err(Error::InvalidTransaction(
                "fee opening does not match commitments",
            ))
        }
    }
}

impl Encodable for FeeOpening {
    fn write(&self, w: &mut Writer) {
        w.put(&self.fee.to_le_bytes())
            .put(&scalar_to_bytes(&self.blinding.expose()));
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let fee = Rhombus::from_raw(r.take_u64_le()?)?;
        let scalar = scalar_from_bytes(&r.take_array()?)?;
        Ok(Self::new(fee, ValueCommitTrapdoor::from_scalar(scalar)))
    }
}

#[cfg(test)]
mod tests {
    use crypto::commitment::ValueCommitment;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::bytes::Encodable;

    #[test]
    fn opening_must_match_the_aggregate_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let blinding = ValueCommitTrapdoor::random(&mut rng);
        let commitment = ValueCommitment::commit(1234, &blinding);
        let opening = FeeOpening::new(Rhombus::from_raw(1234).unwrap(), blinding.clone());
        assert!(opening.verify([&commitment]).is_ok());

        let wrong_amount = FeeOpening::new(Rhombus::from_raw(1235).unwrap(), blinding.clone());
        assert!(wrong_amount.verify([&commitment]).is_err());

        let wrong_blinding = FeeOpening::new(
            Rhombus::from_raw(1234).unwrap(),
            ValueCommitTrapdoor::random(&mut rng),
        );
        assert!(wrong_blinding.verify([&commitment]).is_err());
    }

    #[test]
    fn opening_has_canonical_fixed_length_encoding() {
        let opening = FeeOpening::new(Rhombus::from_raw(42).unwrap(), ValueCommitTrapdoor::zero());
        let bytes = opening.to_vec();
        assert_eq!(bytes.len(), FEE_OPENING_LEN);
        assert_eq!(FeeOpening::from_slice(&bytes), Ok(opening));
    }
}
