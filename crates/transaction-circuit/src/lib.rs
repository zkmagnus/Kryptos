//! Circuit interface used by native shielded transaction validation.
//!
//! This first adapter exposes Rhombus's existing Halo2 transfer relation
//! through a circuit API boundary. The circuit implementation
//! still lives in `circuit`; this crate creates the place to evolve the
//! transfer statement independently without changing transaction callers.
//! It does not change consensus rules or make the circuit user-deployable.

/// The current private transaction circuit backend.
pub mod halo2 {
    pub use circuit::action::{
        ActionCircuit, ActionWitness, CoinWitness, PublicInputs, SpendWitness, K,
    };
    pub use circuit::{Error, Fp};
}

pub use halo2::{ActionWitness, CoinWitness, Error, Fp, PublicInputs, SpendWitness};

/// Version of the circuit adapter API, not the consensus version.
pub const API_VERSION: u16 = 1;
