//! Onion address-exchange limits. Peer identities and self filtering live in
//! the onion-only address book; there is no IP discovery or local DNS policy.

use p2p::peer::Direction;

/// Time between address exchanges on established connections, in seconds.
pub(crate) const EXCHANGE_SECONDS: u64 = 600;
/// Addresses returned by one exchange.
pub(crate) const SAMPLE_SIZE: usize = 100;
/// Minimum ticks between address-list replies to one peer.
pub(crate) const REPLY_SECONDS: u64 = 60;
/// One sampled reply plus the outbound peer's own onion announcement.
pub(crate) const OUTBOUND_ADDR_ALLOWANCE: usize = SAMPLE_SIZE + 1;
/// Inbound peers may announce only one endpoint per exchange.
pub(crate) const INBOUND_ADDR_ALLOWANCE: usize = 1;
/// Extra bounded connection used to verify gossip when outbound slots are full.
pub(crate) const MAX_PROBES: usize = 1;

/// Gossiped addresses allowed per exchange period.
pub(crate) fn addr_allowance(direction: Direction) -> usize {
    match direction {
        Direction::Outbound => OUTBOUND_ADDR_ALLOWANCE,
        Direction::Inbound => INBOUND_ADDR_ALLOWANCE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_gossip_cannot_supply_a_peer_table() {
        assert_eq!(addr_allowance(Direction::Inbound), 1);
        assert_eq!(addr_allowance(Direction::Outbound), SAMPLE_SIZE + 1);
    }
}
