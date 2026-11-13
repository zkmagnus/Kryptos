//! Rhombus's transfer-only program opcode.
//!
//! The imported program tree contains a general VM and monetary proposals.
//! Rhombus already represents transfers with shielded actions and a
//! zero-knowledge proof, so its program opcode is only a dispatch marker. It
//! carries no public recipient or amount and cannot bypass transaction proof
//! verification or value-balance checks.

use core::fmt;

/// Opcode used for coin transfer by the imported XPVM sample.
pub const TRANSFER_OPCODE: u8 = 0x06;

/// The sole supported operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferCall;

/// Errors when decoding a transfer call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The opcode does not identify the transfer operation.
    UnknownOpcode,
    /// Transfer details must come from shielded transaction actions, so this
    /// opcode does not accept a public payload.
    UnexpectedPayload,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// Decode the only supported program call. Recipient and amount remain
/// private in the transaction's coins and are checked by the Rhombus proof.
pub fn decode(opcode: u8, payload: &[u8]) -> Result<TransferCall, DecodeError> {
    if opcode != TRANSFER_OPCODE {
        return Err(DecodeError::UnknownOpcode);
    }
    if !payload.is_empty() {
        return Err(DecodeError::UnexpectedPayload);
    }
    Ok(TransferCall)
}
