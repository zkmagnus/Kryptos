//! Embedded onion-service configuration.

use p2p::address::{NetAddr, PeerKey};
use p2p::transport::{TorSettings, TorStatus};
use tokio::sync::watch;

/// Virtual onion-service ports. Tor runs inside the application process.
#[derive(Clone, Debug)]
pub struct TorConfig {
    /// Virtual P2P port advertised with the service identity.
    pub p2p_port: u16,
    /// Configurable Tor circuit, bootstrap, retry, and application deadlines.
    pub settings: TorSettings,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            p2p_port: 19000,
            settings: TorSettings::default(),
        }
    }
}

impl TorConfig {
    /// Validates the virtual service port.
    ///
    /// # Errors
    /// Rejects port zero.
    pub fn validate(&self) -> crate::Result<()> {
        if self.p2p_port == 0 {
            return Err(crate::Error::Argument(
                "onion P2P port must be nonzero".into(),
            ));
        }
        self.settings.validate()?;
        Ok(())
    }
}

/// Parses an onion-only endpoint without DNS resolution.
///
/// # Errors
/// Rejects malformed addresses and port zero.
pub fn validate_endpoint(endpoint: &str) -> crate::Result<PeerKey> {
    Ok(NetAddr::parse_endpoint(endpoint)?)
}

/// Both halves of the embedded service must remain ready. A closed status
/// channel means the supervisor is gone, even if its last report was ready.
pub(crate) fn service_ready(status: &watch::Receiver<TorStatus>) -> bool {
    let state = status.borrow();
    status.has_changed().is_ok() && state.client_ready && state.onion.is_some()
}
