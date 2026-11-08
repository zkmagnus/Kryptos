//! Consensus constants for transaction shape, issuance and size limits.
//! Explicit public transaction fees are included in coinbase accounting;
//! per-action tax and reserve accounting are removed.

use crate::coin::Rhombus;
use crate::{Error, Result};

/// The only outer transaction version. Transfer SystemCall program version 1
/// is the sole supported transaction and proof layout.
pub const TX_VERSION: u8 = 1;

/// Fixed V1 identity of the public-fee Transfer SystemCall. The distinct ID
/// prevents old layouts from being parsed as this transaction format.
pub const TRANSFER_PROGRAM_ID: [u8; 32] = *b"RHOMBUS\0TRANSFER\0V1FEE\0\0\0\0\0\0\0\0\0\0";
/// Current Transfer SystemCall envelope and proof version, with a public
/// explicit transaction fee and no tax, reserve, or burn field.
pub const TRANSFER_PROGRAM_VERSION: u16 = 1;
/// Entrypoint selector for a shielded transfer.
pub const TRANSFER_ENTRYPOINT: u16 = 1;

/// The only block version.
pub const BLOCK_VERSION: u8 = 1;

/// Identifies one set of consensus rules. Every signature hash binds the
/// branch in force at the block's height, so a transaction signed under
/// one set of rules is invalid under any other: after a fork neither side
/// can replay the other's transactions, and a test network transaction
/// is never valid on the main network. The branch is not part of the
/// transaction bytes; validation supplies it from the chain parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BranchId(u32);

impl BranchId {
    /// Wraps a raw identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// The bytes hashed into a sighash.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// Byte length of the RandomX proof-of-work hash stored in a block header.
pub const POW_SOLUTION_LEN: usize = 32;

/// Most transactions a block may carry. Provisional.
pub const MAX_BLOCK_TRANSACTIONS: usize = 512;

/// Initial block emission: 50 Rhombs.
pub const BLOCK_EMISSION_START: u64 = 50_000_000;
/// Permanent tail emission: 0.781250 Rhombs, reached after six halvings.
pub const TAIL_BLOCK_EMISSION: u64 = 781_250;
/// Number of halvings from the initial emission to the permanent tail.
pub const EMISSION_HALVINGS_TO_TAIL: u64 = 6;
/// Length of each emission interval: approximately six months at 30 seconds
/// per block (365 days per year).
pub const EMISSION_INTERVAL: u64 = 100_000;

/// The block subsidy at `height`. Genesis pays nothing.
pub fn subsidy(height: u32) -> Rhombus {
    if height == 0 {
        return Rhombus::ZERO;
    }
    let completed_intervals = u64::from(height - 1) / EMISSION_INTERVAL;
    let raw = if completed_intervals >= EMISSION_HALVINGS_TO_TAIL {
        TAIL_BLOCK_EMISSION
    } else {
        BLOCK_EMISSION_START >> completed_intervals
    };
    Rhombus::from_raw(raw).unwrap_or(Rhombus::ZERO)
}

/// The height of the block after one at `height`.
///
/// # Errors
/// Returns [`Error::HeightExhausted`] at `u32::MAX`: the chain has no
/// defined continuation, so producing or importing a block there is
/// refused rather than letting a saturated height overwrite the index.
pub fn next_height(height: u32) -> Result<u32> {
    height.checked_add(1).ok_or(Error::HeightExhausted)
}

/// Allowed numbers of actions per transaction. A transaction is padded with
/// dummy actions up to the smallest class that fits.
pub const ACTION_CLASSES: [usize; 4] = [2, 4, 8, 16];

/// The largest action class.
pub const MAX_ACTIONS: usize = 16;

/// The exact proof length of a bundle with `actions` actions.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] if `actions` is not a class.
pub fn proof_len(actions: usize) -> Result<usize> {
    systemcall_proof::proof_len(actions).ok_or(Error::InvalidTransaction(
        "action count is not an allowed class",
    ))
}

/// The smallest action class that fits `needed` actions.
///
/// # Errors
/// Returns [`Error::TooManyActions`] above [`MAX_ACTIONS`].
pub fn action_class_for(needed: usize) -> Result<usize> {
    ACTION_CLASSES
        .iter()
        .copied()
        .find(|class| *class >= needed)
        .ok_or(Error::TooManyActions)
}

/// Whether `count` is an allowed number of actions.
pub fn is_action_class(count: usize) -> bool {
    ACTION_CLASSES.contains(&count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_ascending_powers_of_two_up_to_max() {
        assert_eq!(ACTION_CLASSES.last(), Some(&MAX_ACTIONS));
        for window in ACTION_CLASSES.windows(2) {
            assert_eq!(window[0] * 2, window[1]);
        }
    }

    #[test]
    fn class_is_the_smallest_that_fits() {
        assert_eq!(action_class_for(0), Ok(2));
        assert_eq!(action_class_for(1), Ok(2));
        assert_eq!(action_class_for(2), Ok(2));
        assert_eq!(action_class_for(3), Ok(4));
        assert_eq!(action_class_for(9), Ok(16));
        assert_eq!(action_class_for(16), Ok(16));
        assert_eq!(action_class_for(17), Err(Error::TooManyActions));
    }

    #[test]
    fn branch_ids_encode_little_endian_and_compare_by_value() {
        assert_eq!(BranchId::new(0x0403_0201).to_bytes(), [1, 2, 3, 4]);
        assert_eq!(BranchId::new(7), BranchId::new(7));
        assert_ne!(BranchId::new(7), BranchId::new(8));
    }

    #[test]
    fn next_height_counts_up_and_refuses_exhaustion() {
        assert_eq!(next_height(0), Ok(1));
        assert_eq!(next_height(u32::MAX - 1), Ok(u32::MAX));
        assert_eq!(next_height(u32::MAX), Err(Error::HeightExhausted));
    }

    #[test]
    fn membership_matches_classes() {
        assert!(is_action_class(4));
        assert!(!is_action_class(3));
        assert!(!is_action_class(0));
    }

    #[test]
    fn proof_len_exists_exactly_for_classes() {
        for class in ACTION_CLASSES {
            assert!(proof_len(class).is_ok());
        }
        assert!(proof_len(3).is_err());
    }

    #[test]
    fn emission_schedule_halves_from_fifty_to_a_permanent_tail() {
        assert_eq!(subsidy(0), Rhombus::ZERO);
        assert_eq!(subsidy(1).raw(), BLOCK_EMISSION_START);
        assert_eq!(subsidy(100_000).raw(), BLOCK_EMISSION_START);
        assert_eq!(subsidy(100_001).raw(), BLOCK_EMISSION_START / 2);
        assert_eq!(subsidy(200_001).raw(), BLOCK_EMISSION_START / 4);
        assert_eq!(subsidy(500_001).raw(), BLOCK_EMISSION_START / 32);
        assert_eq!(subsidy(600_001).raw(), TAIL_BLOCK_EMISSION);
        assert_eq!(subsidy(u32::MAX).raw(), TAIL_BLOCK_EMISSION);
    }
}
