//! The message set. Every message is `tag || payload` with the canonical
//! encodings of the protocol crate; lists carry a `u32` count bounded by
//! a per-list limit. There is no user agent: all nodes use the same version
//! layout and message set.

use crate::address::{NetAddr, PeerKey};
use protocol::block::{Block, BlockHash, BlockHeader};
use protocol::bytes::{Encodable, Reader, Writer};
use protocol::consensus::MAX_BLOCK_TRANSACTIONS;
use protocol::transaction::{Transaction, TxId};

use crate::{Error, Result};

/// The only protocol version.
pub const PROTOCOL_VERSION: u32 = 4;
/// Upper bound on one encoded message, large enough for a maximum-size block.
pub const MAX_MESSAGE_LEN: usize = 50 * 1024 * 1024;
/// Most inventory items in one message.
pub const MAX_INVENTORY: usize = 50_000;
/// Most headers in one message.
pub const MAX_HEADERS: usize = 2_000;
/// Most locator hashes in one message.
pub const MAX_LOCATOR: usize = 64;
/// Most addresses in one message.
pub const MAX_ADDRESSES: usize = 1_000;

/// What a node announces about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    /// Protocol version.
    pub version: u32,
    /// Fresh per-connection random nonce for self-detection and duplicate linking.
    /// An outbound nonce must never be reused in responses on inbound streams.
    pub nonce: u64,
    /// Height of the sender's tip.
    pub best_height: u32,
    /// Genesis hash, which identifies the network.
    pub genesis: BlockHash,
    /// Sender's clock, seconds since the epoch.
    pub timestamp: u64,
    /// Advertised application capabilities; bit zero means full block service.
    pub services: u64,
    /// Claimed onion endpoint; an inbound claim alone is not authenticated.
    pub onion: Option<PeerKey>,
}

/// A Tor v3 service endpoint and the last time it was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddr {
    /// The onion service's identity.
    pub addr: NetAddr,
    /// The port.
    pub port: u16,
    /// When the address was last seen alive, seconds since the epoch.
    pub last_seen: u64,
}

impl PeerAddr {
    /// A service endpoint with a gossip timestamp.
    pub fn new(addr: NetAddr, port: u16, last_seen: u64) -> Self {
        Self {
            addr,
            port,
            last_seen,
        }
    }

    /// The address without its timestamp, for use as a key.
    pub fn key(&self) -> PeerKey {
        (self.addr, self.port)
    }

    /// Appends the Tor-only addrv2 endpoint followed by its timestamp.
    pub(crate) fn write(&self, w: &mut Writer) {
        self.addr.write(self.port, w);
        w.put_u64_le(self.last_seen);
    }

    /// Reads the layout [`PeerAddr::write`] produces.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let (addr, port) = NetAddr::read(r)?;
        Ok(Self::new(addr, port, r.take_u64_le()?))
    }
}

/// A block or transaction reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// A block by hash.
    Block(BlockHash),
    /// A transaction by id.
    Tx(TxId),
}

/// A protocol message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Handshake: who we are.
    Version(VersionInfo),
    /// Handshake: version accepted.
    Verack,
    /// Link simultaneous opposite-direction connections without delaying readiness.
    /// The sender forwards an inbound Version nonce exclusively over its already
    /// authenticated outbound stream to the claimed onion. The receiver accepts
    /// it only if it matches a live outbound nonce sent to that same onion.
    /// Never echo a token on the inbound stream that supplied it.
    ConnectionLink(u64),
    /// Keepalive request.
    Ping(u64),
    /// Keepalive reply.
    Pong(u64),
    /// Ask for known addresses.
    GetAddr,
    /// Known addresses.
    Addr(Vec<PeerAddr>),
    /// Ask for headers after the first locator hash we recognize.
    GetHeaders {
        /// Hashes from our tip backwards, dense then sparse.
        locator: Vec<BlockHash>,
        /// Stop at this hash, or zero for as many as allowed.
        stop: BlockHash,
    },
    /// Headers in chain order.
    Headers(Vec<BlockHeader>),
    /// Announce items we have.
    Inv(Vec<Inventory>),
    /// Request items.
    GetData(Vec<Inventory>),
    /// Items we do not have.
    NotFound(Vec<Inventory>),
    /// A full block.
    Block(Box<Block>),
    /// A transaction in the fluff phase, to be relayed to everyone.
    Tx(Box<Transaction>),
    /// A transaction in the stem phase, to be relayed to one peer.
    StemTx(Box<Transaction>),
    /// A new block as its header, its coinbase, and the ids of the other
    /// transactions, which the receiver usually already has.
    CompactBlock(Box<CompactBlock>),
    /// Request the transactions at these indices of a compact block.
    GetBlockTxn {
        /// The block.
        hash: BlockHash,
        /// Indices into the block's transaction list, ascending.
        indices: Vec<u32>,
    },
    /// The requested transactions of a block, in index order.
    BlockTxn {
        /// The block.
        hash: BlockHash,
        /// The transactions.
        transactions: Vec<Transaction>,
    },
}

/// A block with the transactions the receiver likely has left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    /// The header.
    pub header: BlockHeader,
    /// The coinbase, which no mempool holds.
    pub coinbase: Transaction,
    /// Ids of the remaining transactions, in block order.
    pub txids: Vec<TxId>,
}

impl CompactBlock {
    /// The compact form of `block`.
    ///
    /// # Errors
    /// Fails if the block has no transactions.
    pub fn from_block(block: &Block) -> Result<Self> {
        let (coinbase, rest) = block.transactions().split_first().ok_or(Error::Protocol(
            protocol::Error::InvalidBlock("no coinbase"),
        ))?;
        Ok(Self {
            header: block.header().clone(),
            coinbase: coinbase.clone(),
            txids: rest.iter().map(Transaction::txid).collect(),
        })
    }

    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

mod tag {
    pub const VERSION: u8 = 1;
    pub const VERACK: u8 = 2;
    pub const PING: u8 = 3;
    pub const PONG: u8 = 4;
    pub const GET_ADDR: u8 = 5;
    pub const ADDR: u8 = 6;
    pub const GET_HEADERS: u8 = 7;
    pub const HEADERS: u8 = 8;
    pub const INV: u8 = 9;
    pub const GET_DATA: u8 = 10;
    pub const NOT_FOUND: u8 = 11;
    pub const BLOCK: u8 = 12;
    pub const TX: u8 = 13;
    pub const STEM_TX: u8 = 14;
    pub const COMPACT_BLOCK: u8 = 15;
    pub const GET_BLOCK_TXN: u8 = 16;
    pub const BLOCK_TXN: u8 = 17;
    pub const CONNECTION_LINK: u8 = 18;
}

impl Message {
    /// The type tag.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Version(_) => tag::VERSION,
            Self::Verack => tag::VERACK,
            Self::ConnectionLink(_) => tag::CONNECTION_LINK,
            Self::Ping(_) => tag::PING,
            Self::Pong(_) => tag::PONG,
            Self::GetAddr => tag::GET_ADDR,
            Self::Addr(_) => tag::ADDR,
            Self::GetHeaders { .. } => tag::GET_HEADERS,
            Self::Headers(_) => tag::HEADERS,
            Self::Inv(_) => tag::INV,
            Self::GetData(_) => tag::GET_DATA,
            Self::NotFound(_) => tag::NOT_FOUND,
            Self::Block(_) => tag::BLOCK,
            Self::Tx(_) => tag::TX,
            Self::StemTx(_) => tag::STEM_TX,
            Self::CompactBlock(_) => tag::COMPACT_BLOCK,
            Self::GetBlockTxn { .. } => tag::GET_BLOCK_TXN,
            Self::BlockTxn { .. } => tag::BLOCK_TXN,
        }
    }

    /// Encodes to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.put_u8(self.tag());
        match self {
            Self::Version(v) => {
                w.put(&v.version.to_le_bytes())
                    .put_u64_le(v.nonce)
                    .put(&v.best_height.to_le_bytes())
                    .put(v.genesis.as_bytes())
                    .put_u64_le(v.timestamp)
                    .put_u64_le(v.services);
                w.put_u8(u8::from(v.onion.is_some()));
                if let Some((addr, port)) = v.onion {
                    addr.write(port, &mut w);
                }
            }
            Self::Verack | Self::GetAddr => {}
            Self::Ping(n) | Self::Pong(n) | Self::ConnectionLink(n) => {
                w.put_u64_le(*n);
            }
            Self::Addr(addrs) => {
                put_count(&mut w, addrs.len());
                for a in addrs {
                    a.write(&mut w);
                }
            }
            Self::GetHeaders { locator, stop } => {
                put_count(&mut w, locator.len());
                for h in locator {
                    w.put(h.as_bytes());
                }
                w.put(stop.as_bytes());
            }
            Self::Headers(headers) => {
                put_count(&mut w, headers.len());
                for h in headers {
                    h.write(&mut w);
                }
            }
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                put_count(&mut w, items.len());
                for item in items {
                    match item {
                        Inventory::Block(h) => {
                            w.put_u8(0).put(h.as_bytes());
                        }
                        Inventory::Tx(id) => {
                            w.put_u8(1).put(id.as_bytes());
                        }
                    }
                }
            }
            Self::Block(b) => b.write(&mut w),
            Self::Tx(t) | Self::StemTx(t) => t.write(&mut w),
            Self::CompactBlock(c) => {
                c.header.write(&mut w);
                c.coinbase.write(&mut w);
                put_count(&mut w, c.txids.len());
                for id in &c.txids {
                    w.put(id.as_bytes());
                }
            }
            Self::GetBlockTxn { hash, indices } => {
                w.put(hash.as_bytes());
                put_count(&mut w, indices.len());
                for i in indices {
                    w.put(&i.to_le_bytes());
                }
            }
            Self::BlockTxn { hash, transactions } => {
                w.put(hash.as_bytes());
                put_count(&mut w, transactions.len());
                for t in transactions {
                    t.write(&mut w);
                }
            }
        }
        w.into_bytes()
    }

    /// Decodes a complete message.
    ///
    /// # Errors
    /// Fails on an unknown tag, an over-long list, or malformed payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tag = r.take_u8()?;
        let message = match tag {
            tag::VERSION => Self::Version(VersionInfo {
                version: u32::from_le_bytes(r.take_array()?),
                nonce: r.take_u64_le()?,
                best_height: u32::from_le_bytes(r.take_array()?),
                genesis: BlockHash::from_bytes(r.take_array()?),
                timestamp: r.take_u64_le()?,
                services: r.take_u64_le()?,
                onion: match r.take_u8()? {
                    0 => None,
                    1 => Some(NetAddr::read(&mut r)?),
                    _ => return Err(Error::BadAddress("invalid onion claim flag")),
                },
            }),
            tag::VERACK => Self::Verack,
            tag::CONNECTION_LINK => Self::ConnectionLink(r.take_u64_le()?),
            tag::PING => Self::Ping(r.take_u64_le()?),
            tag::PONG => Self::Pong(r.take_u64_le()?),
            tag::GET_ADDR => Self::GetAddr,
            tag::ADDR => {
                let count = take_count(&mut r, MAX_ADDRESSES, "addresses")?;
                let addrs = (0..count)
                    .map(|_| PeerAddr::read(&mut r))
                    .collect::<Result<Vec<_>>>()?;
                Self::Addr(addrs)
            }
            tag::GET_HEADERS => {
                let count = take_count(&mut r, MAX_LOCATOR, "locator")?;
                let locator = (0..count)
                    .map(|_| Ok(BlockHash::from_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::GetHeaders {
                    locator,
                    stop: BlockHash::from_bytes(r.take_array()?),
                }
            }
            tag::HEADERS => {
                let count = take_count(&mut r, MAX_HEADERS, "headers")?;
                let headers = (0..count)
                    .map(|_| Ok(BlockHeader::read(&mut r)?))
                    .collect::<Result<Vec<_>>>()?;
                Self::Headers(headers)
            }
            tag::INV | tag::GET_DATA | tag::NOT_FOUND => {
                let count = take_count(&mut r, MAX_INVENTORY, "inventory")?;
                let items = (0..count)
                    .map(|_| read_inventory(&mut r))
                    .collect::<Result<Vec<_>>>()?;
                match tag {
                    tag::INV => Self::Inv(items),
                    tag::GET_DATA => Self::GetData(items),
                    _ => Self::NotFound(items),
                }
            }
            tag::BLOCK => Self::Block(Box::new(Block::read(&mut r)?)),
            tag::TX => Self::Tx(Box::new(Transaction::read(&mut r)?)),
            tag::STEM_TX => Self::StemTx(Box::new(Transaction::read(&mut r)?)),
            tag::COMPACT_BLOCK => {
                let header = BlockHeader::read(&mut r)?;
                let coinbase = Transaction::read(&mut r)?;
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "txids")?;
                let txids = (0..count)
                    .map(|_| Ok(TxId::from_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::CompactBlock(Box::new(CompactBlock {
                    header,
                    coinbase,
                    txids,
                }))
            }
            tag::GET_BLOCK_TXN => {
                let hash = BlockHash::from_bytes(r.take_array()?);
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "indices")?;
                let indices = (0..count)
                    .map(|_| Ok(u32::from_le_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::GetBlockTxn { hash, indices }
            }
            tag::BLOCK_TXN => {
                let hash = BlockHash::from_bytes(r.take_array()?);
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "transactions")?;
                let transactions = (0..count)
                    .map(|_| Ok(Transaction::read(&mut r)?))
                    .collect::<Result<Vec<_>>>()?;
                Self::BlockTxn { hash, transactions }
            }
            other => return Err(Error::UnknownTag(other)),
        };
        r.finish()?;
        Ok(message)
    }
}

pub(crate) fn put_count(w: &mut Writer, count: usize) {
    // Every list is bounded by a limit far below u32::MAX.
    w.put(&u32::try_from(count).unwrap_or(u32::MAX).to_le_bytes());
}

pub(crate) fn take_count(r: &mut Reader<'_>, max: usize, what: &'static str) -> Result<usize> {
    let count = usize::try_from(u32::from_le_bytes(r.take_array()?))
        .map_err(|_| Error::ListTooLong(what))?;
    if count > max {
        return Err(Error::ListTooLong(what));
    }
    Ok(count)
}

fn read_inventory(r: &mut Reader<'_>) -> Result<Inventory> {
    match r.take_u8()? {
        0 => Ok(Inventory::Block(BlockHash::from_bytes(r.take_array()?))),
        1 => Ok(Inventory::Tx(TxId::from_bytes(r.take_array()?))),
        _ => Err(Error::Protocol(protocol::Error::Malformed(
            "inventory kind",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crypto::pallas;
    use protocol::block::empty_header;
    use protocol::transaction::Anchor;

    use super::*;

    fn samples() -> Vec<Message> {
        let header = empty_header(
            3,
            BlockHash::from_bytes([1; 32]),
            Anchor::from_base(pallas::Base::from(2u64)),
        );
        vec![
            Message::Version(VersionInfo {
                version: PROTOCOL_VERSION,
                nonce: 7,
                best_height: 9,
                genesis: BlockHash::from_bytes([4; 32]),
                timestamp: 1_000,
                services: 1,
                onion: Some((NetAddr::TorV3([7; 32]), 19000)),
            }),
            Message::Verack,
            Message::ConnectionLink(3),
            Message::Ping(1),
            Message::Pong(2),
            Message::GetAddr,
            Message::Addr(vec![PeerAddr::new(NetAddr::TorV3([1; 32]), 8333, 5)]),
            Message::GetHeaders {
                locator: vec![BlockHash::from_bytes([3; 32])],
                stop: BlockHash::ZERO,
            },
            Message::Headers(vec![header.clone(), header.clone()]),
            Message::Inv(vec![
                Inventory::Block(BlockHash::ZERO),
                Inventory::Tx(TxId::from_bytes([8; 32])),
            ]),
            Message::GetData(vec![Inventory::Tx(TxId::from_bytes([8; 32]))]),
            Message::NotFound(vec![]),
            Message::Block(Box::new(Block::new(header.clone(), Vec::new()))),
            Message::GetBlockTxn {
                hash: BlockHash::ZERO,
                indices: vec![1, 3],
            },
            Message::BlockTxn {
                hash: BlockHash::ZERO,
                transactions: vec![],
            },
        ]
    }

    #[test]
    fn every_message_roundtrips() {
        for message in samples() {
            let bytes = message.encode();
            assert_eq!(
                Message::decode(&bytes).unwrap(),
                message,
                "{}",
                message.tag()
            );
        }
    }

    #[test]
    fn tags_are_distinct() {
        let mut tags: Vec<u8> = samples().iter().map(Message::tag).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), samples().len());
    }

    #[test]
    fn unknown_tags_trailing_bytes_and_long_lists_are_rejected() {
        assert!(matches!(
            Message::decode(&[200]),
            Err(Error::UnknownTag(200))
        ));
        let mut bytes = Message::Verack.encode();
        bytes.push(0);
        assert!(Message::decode(&bytes).is_err());
        let mut long = vec![tag::INV];
        long.extend_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(
            Message::decode(&long),
            Err(Error::ListTooLong("inventory"))
        ));
        assert!(Message::decode(&[tag::PING, 1, 2]).is_err(), "truncated");
    }

    #[test]
    fn connection_link_requires_exactly_one_nonce() {
        for nonce in [0, 1, u64::MAX] {
            let message = Message::ConnectionLink(nonce);
            let bytes = message.encode();
            assert_eq!(bytes.len(), 9);
            assert_eq!(bytes.first(), Some(&tag::CONNECTION_LINK));
            assert_eq!(Message::decode(&bytes).unwrap(), message);
            for len in 0..bytes.len() {
                assert!(Message::decode(&bytes[..len]).is_err());
            }
            let mut extra = bytes;
            extra.push(0);
            assert!(Message::decode(&extra).is_err());
        }
    }

    #[test]
    fn compact_block_needs_a_coinbase() {
        let header = empty_header(
            0,
            BlockHash::ZERO,
            Anchor::from_base(pallas::Base::from(1u64)),
        );
        assert!(CompactBlock::from_block(&Block::new(header, Vec::new())).is_err());
    }

    #[test]
    fn tor_addresses_use_the_identity_and_service_port_as_key() {
        let addr = NetAddr::TorV3([1; 32]);
        let a = PeerAddr::new(addr, 1, 0);
        assert_eq!(a.key(), (addr, 1));
    }
}
