//! Proof API for private protocol transactions.
//!
//! The current implementation delegates to Rhombus's Halo2 proof engine.
//! Consensus callers depend on this API rather than directly selecting a
//! proving backend. Changing the backend or verifier remains a consensus
//! change and requires an explicit consensus revision and activation rule.

pub use circuit::proof::{
    proof_len, PrivateTransactionProofV2, Proof, ProofBatch, ProvingKey, VerifyingKey,
};
pub use transaction_circuit::Error;

/// Version of the proof adapter API, not the wire transaction
/// version. V2 exposes a top-level private-fee transaction proof envelope.
pub const API_VERSION: u16 = 1;

/// Name of the proving backend currently used by this adapter.
pub const BACKEND: &str = "halo2";
