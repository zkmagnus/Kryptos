//! Public transaction fee, priced per encoded byte.

use crate::amount::RawCoin;
use crate::consensus::subsidy;
use crate::{Error, Result};

/// Price per encoded byte, in rawcoin.
pub const FEE_PER_BYTE: u64 = 1;

/// Fee for a transaction whose exact encoded length is `len`.
pub fn fee_for_len(len: usize) -> Result<RawCoin> {
    let len = u64::try_from(len).map_err(|_| Error::InvalidTransaction("fee overflow"))?;
    let raw = FEE_PER_BYTE
        .checked_mul(len)
        .ok_or(Error::InvalidTransaction("fee overflow"))?;
    RawCoin::from_raw(raw)
}

/// Sum of the fees declared by a block's transactions, overflow-checked.
pub fn total_fees(fees: impl IntoIterator<Item = RawCoin>) -> Result<RawCoin> {
    let mut total = 0u64;
    for fee in fees {
        total = total
            .checked_add(fee.raw())
            .ok_or(Error::InvalidBlock("fee sum overflow"))?;
    }
    RawCoin::from_raw(total)
}

/// The coinbase mint at `height`: subsidy plus all included transfer fees.
pub fn block_mint(
    height: u32,
    transfer_fees: impl IntoIterator<Item = RawCoin>,
) -> Result<RawCoin> {
    subsidy(height).checked_add(total_fees(transfer_fees)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_is_one_raw_unit_per_byte() {
        assert_eq!(fee_for_len(2_048).unwrap().raw(), 2_048);
    }

    #[test]
    fn total_fees_rejects_overflow() {
        let max = RawCoin::from_raw(u64::MAX >> 1).unwrap();
        assert!(total_fees([max, max, max]).is_err());
    }

    #[test]
    fn total_fees_sums_values() {
        let fees = [RawCoin::from_raw(3).unwrap(), RawCoin::from_raw(5).unwrap()];
        assert_eq!(total_fees(fees).unwrap().raw(), 8);
    }

    #[test]
    fn block_mint_adds_subsidy_and_transfer_fees() {
        let fees = [
            RawCoin::from_raw(7).unwrap(),
            RawCoin::from_raw(11).unwrap(),
        ];
        assert_eq!(block_mint(1, fees).unwrap().raw(), subsidy(1).raw() + 18);
        assert!(block_mint(1, [RawCoin::MAX]).is_err());
    }
}
