//! Consensus constants for transaction shape, issuance and size limits.
//! Transaction fees are relay metadata and block reward conservation is
//! checked with the block-wide value-binding signature.

use crate::coin::Rhombus;
use crate::{Error, Result};

/// The private-fee transaction format with an explicit SystemCall opcode.
pub const TX_VERSION: u8 = 1;

/// The only supported VM operation, also encoded in each transaction.
pub const TRANSFER_OPCODE: u8 = program_vm::TRANSFER_OPCODE;
/// Entrypoint selector for a shielded transfer.
pub const TRANSFER_ENTRYPOINT: u16 = 1;
/// Entry point for a block's coinbase transfer. Its aggregate net is negative.
pub const COINBASE_ENTRYPOINT: u16 = 2;

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

/// Initial block emission: 12.5 Rhombs.
pub const BLOCK_EMISSION_START: u64 = 2_500_000_000;
/// Permanent tail emission: 0.125 Rhombs.
pub const TAIL_BLOCK_EMISSION: u64 = 25_000_000;
/// Number of emission intervals before subsidy reaches the permanent tail.
pub const EMISSION_HALVINGS_TO_TAIL: u64 = 1;
/// Length of each emission interval: approximately six months at 30 seconds
/// per block (365 days per year).
pub const EMISSION_INTERVAL: u64 = 1_000_000;

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
    fn emission_reaches_the_permanent_tail_after_one_interval() {
        assert_eq!(subsidy(0), Rhombus::ZERO);
        assert_eq!(subsidy(1).raw(), BLOCK_EMISSION_START);
        assert_eq!(subsidy(100_000).raw(), BLOCK_EMISSION_START);
        assert_eq!(BLOCK_EMISSION_START, 12_500_000);
        assert_eq!(TAIL_BLOCK_EMISSION, 125_000);
        assert_eq!(subsidy(1_000_001).raw(), TAIL_BLOCK_EMISSION);
        assert_eq!(subsidy(u32::MAX).raw(), TAIL_BLOCK_EMISSION);
    }
}
