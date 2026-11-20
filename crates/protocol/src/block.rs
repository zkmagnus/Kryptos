//! Blocks: a versioned header over a list of transactions.
//!
//! ```text
//! v1 header = version || prev_hash || height || timestamp || commitment_root
//!             || nullifier_root || state_root || tx_root || body_root
//!             || history_root || target || nonce || randomx_hash
//! randomx_hash = RandomX(network_key, versioned_domain || pow_header || nonce)
//! hash   = BLAKE2b-256_{BLOCK_HASH}(header)
//! tx_root = BLAKE2b Merkle commitment over indexed transaction ids
//! ```
//!
//! `commitment_root` is the note commitment tree root *after* applying
//! the block, so it doubles as the anchor later transactions may use.
//! Proof-of-work semantics of `target`, `nonce` and `solution` live in the
//! chain crate; the protocol only fixes their layout.

use crypto::encoding::{to_hex, Encoded};
use crypto::hash::{blake2b_short, BLOCK_HASH, BLOCK_TRANSITION, SHORT_OUTPUT_LEN};
use ff::Field;

use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS, POW_SOLUTION_LEN};
use crate::transaction::{Anchor, Transaction};
use crate::{Error, Result};

/// A block identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BlockHash([u8; SHORT_OUTPUT_LEN]);

impl BlockHash {
    /// The all-zero hash, used as the previous hash of the genesis block.
    pub const ZERO: Self = Self([0; SHORT_OUTPUT_LEN]);

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; SHORT_OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; SHORT_OUTPUT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlockHash({self})")
    }
}

impl core::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

/// The proof-of-work solution bytes, fixed length.
#[derive(Clone, PartialEq, Eq)]
pub struct PowSolution([u8; POW_SOLUTION_LEN]);

impl PowSolution {
    /// Wraps solution bytes.
    pub fn from_bytes(bytes: [u8; POW_SOLUTION_LEN]) -> Self {
        Self(bytes)
    }

    /// An all-zero solution, for tests and for headers under construction.
    pub fn empty() -> Self {
        Self([0; POW_SOLUTION_LEN])
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; POW_SOLUTION_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for PowSolution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PowSolution({POW_SOLUTION_LEN} bytes)")
    }
}

/// The block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Format version.
    pub version: u8,
    /// Hash of the previous block, zero for genesis.
    pub prev_hash: BlockHash,
    /// Height, zero for genesis.
    pub height: u32,
    /// Seconds since the Unix epoch.
    pub timestamp: u64,
    /// Coin commitment tree root after this block.
    pub commitment_root: Anchor,
    /// Spent-nullifier set root after this block.
    pub nullifier_root: Anchor,
    /// Composite state root after this block.
    pub state_root: Anchor,
    /// Commitment to the transactions.
    pub tx_root: [u8; SHORT_OUTPUT_LEN],
    /// Complete body commitment, excluding the header.
    pub body_root: [u8; SHORT_OUTPUT_LEN],
    /// Header-history root through the parent.
    pub history_root: [u8; SHORT_OUTPUT_LEN],
    /// Compact difficulty target.
    pub target: u32,
    /// Proof-of-work nonce.
    pub nonce: Encoded,
    /// Proof-of-work solution.
    pub solution: PowSolution,
}

/// Byte length of the sole supported v1 block header.
pub const HEADER_LEN_V1: usize =
    1 + 32 + 4 + 8 + 32 + 32 + 32 + 32 + 32 + 32 + 4 + 32 + POW_SOLUTION_LEN;
/// Fixed header length for the current and only format.
pub const HEADER_LEN: usize = HEADER_LEN_V1;

/// Returns the encoded header size for a recognized block version.
pub const fn header_len_for_version(version: u8) -> Option<usize> {
    match version {
        BLOCK_VERSION => Some(HEADER_LEN_V1),
        _ => None,
    }
}

impl BlockHeader {
    /// The canonical serialized size for this header's version.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN_V1
    }

    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        BlockHash(blake2b_short(BLOCK_HASH, &[&self.to_vec()]))
    }

    /// A domain-separated commitment to the state-transition header fields.
    ///
    /// This commits to version, ancestry, height, timestamp, state roots,
    /// transaction root, and target. It intentionally excludes the nonce and
    /// proof-of-work solution so a HistoryStep statement has a stable digest
    /// while a miner searches for a valid solution.
    pub fn transition_hash(&self) -> [u8; SHORT_OUTPUT_LEN] {
        let mut w = Writer::with_capacity(self.encoded_len().saturating_sub(64));
        self.write_pow_input(&mut w);
        blake2b_short(BLOCK_TRANSITION, &[&w.into_bytes()])
    }

    /// The domain-separated header and nonce used as `RandomX` input.
    pub fn pow_input(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.encoded_len());
        self.write_pow_input(&mut w);
        w.put(&self.nonce);
        let domain: &[u8] = b"Kryptos:RandomX:v1";
        let mut input = domain.to_vec();
        input.extend_from_slice(&w.into_bytes());
        input
    }

    fn write_pow_input(&self, w: &mut Writer) {
        w.put_u8(self.version)
            .put(self.prev_hash.as_bytes())
            .put(&self.height.to_le_bytes())
            .put_u64_le(self.timestamp)
            .put(&self.commitment_root.to_bytes());
        w.put(&self.nullifier_root.to_bytes())
            .put(&self.state_root.to_bytes())
            .put(&self.tx_root)
            .put(&self.body_root)
            .put(&self.history_root)
            .put(&self.target.to_le_bytes());
    }
}

impl Encodable for BlockHeader {
    fn write(&self, w: &mut Writer) {
        self.write_pow_input(w);
        w.put(&self.nonce).put(self.solution.as_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        if header_len_for_version(version).is_none() {
            return Err(Error::Malformed("unknown block header version"));
        }
        let prev_hash = BlockHash::from_bytes(r.take_array()?);
        let height = u32::from_le_bytes(r.take_array()?);
        let timestamp = r.take_u64_le()?;
        let commitment_root = Anchor::read(r)?;
        let nullifier_root = Anchor::read(r)?;
        let state_root = Anchor::read(r)?;
        let tx_root = r.take_array()?;
        let body_root = r.take_array()?;
        let history_root = r.take_array()?;
        Ok(Self {
            version,
            prev_hash,
            height,
            timestamp,
            commitment_root,
            nullifier_root,
            state_root,
            tx_root,
            body_root,
            history_root,
            target: u32::from_le_bytes(r.take_array()?),
            nonce: r.take_array()?,
            solution: PowSolution::from_bytes(r.take_array()?),
        })
    }
}

/// A block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl Block {
    /// Assembles a block. Consistency of `header.tx_root` with the
    /// transactions is checked by [`Block::check_tx_root`].
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// The header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The transactions.
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// The commitment to this block's transactions.
    pub fn tx_root(&self) -> [u8; SHORT_OUTPUT_LEN] {
        tx_root(self.transactions.iter().map(Transaction::txid))
    }

    /// Whether the header commits to exactly these transactions.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlock`] on a mismatch.
    pub fn check_tx_root(&self) -> Result<()> {
        if self.tx_root() == self.header.tx_root {
            Ok(())
        } else {
            Err(Error::InvalidBlock("transaction root mismatch"))
        }
    }

    /// Checks the commitment to complete canonical body bytes.
    ///
    /// Older encodings do not contain this commitment. Transaction signature
    /// and action-proof validation remain the chain validator's responsibility.
    ///
    /// # Errors
    /// Fails on a size violation or a mismatching body commitment.
    pub fn check_body_root(&self) -> Result<()> {
        if crate::body_tree::body_root(&self.transactions)? != self.header.body_root {
            return Err(Error::InvalidBlock("body root mismatch"));
        }
        Ok(())
    }

    /// Returns one complete-body chunk and its inclusion path.
    /// The path must be checked against an authenticated header body root.
    ///
    /// # Errors
    /// Rejects an out-of-range chunk, malformed body, or mismatching root.
    pub fn body_chunk(&self, index: usize) -> Result<(Vec<u8>, crate::body_tree::BodyMerklePath)> {
        if self.header.version != BLOCK_VERSION {
            return Err(Error::InvalidBlock("body chunks require a v1 header"));
        }
        self.check_body_root()?;
        let bytes = crate::body_tree::body_bytes(&self.transactions)?;
        let path = crate::body_tree::body_merkle_path(&bytes, index)?;
        let chunk = bytes
            .chunks(crate::body_tree::BODY_CHUNK_SIZE)
            .nth(index)
            .ok_or(Error::Malformed("body chunk index"))?
            .to_vec();
        Ok((chunk, path))
    }

    /// Parses a downloaded body against an authenticated header.
    /// Transaction authorization, state transitions and PoW still require the
    /// normal chain validator after reassembly.
    ///
    /// # Errors
    /// Rejects a wrong body root, excessive count, malformed transaction,
    /// trailing bytes, or a transaction-id root mismatch.
    pub fn from_body(header: BlockHeader, body: &[u8]) -> Result<Self> {
        if header.version != BLOCK_VERSION
            || crate::body_tree::body_root_from_bytes(body)? != header.body_root
        {
            return Err(Error::InvalidBlock("body root mismatch"));
        }
        let mut reader = Reader::new(body);
        let count = usize::try_from(u32::from_le_bytes(reader.take_array()?))
            .map_err(|_| Error::Malformed("transaction count"))?;
        if count > MAX_BLOCK_TRANSACTIONS {
            return Err(Error::InvalidBlock("too many transactions"));
        }
        let transactions = (0..count)
            .map(|_| Transaction::read(&mut reader))
            .collect::<Result<Vec<_>>>()?;
        reader.finish()?;
        let block = Self::new(header, transactions);
        block.check_tx_root()?;
        Ok(block)
    }
}

/// Transaction-id Merkle APIs, retained here for compatibility.
pub use crate::tx_tree::{tx_merkle_path, tx_root, TxMerklePath};

impl Encodable for Block {
    fn write(&self, w: &mut Writer) {
        self.header.write(w);
        // Bounded by MAX_BLOCK_TRANSACTIONS in valid blocks.
        let count = u32::try_from(self.transactions.len()).unwrap_or(u32::MAX);
        w.put(&count.to_le_bytes());
        for tx in &self.transactions {
            tx.write(w);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let header = BlockHeader::read(r)?;
        let count = usize::try_from(u32::from_le_bytes(r.take_array()?))
            .map_err(|_| Error::Malformed("transaction count"))?;
        if count > MAX_BLOCK_TRANSACTIONS {
            return Err(Error::InvalidBlock("too many transactions"));
        }
        let transactions = (0..count)
            .map(|_| Transaction::read(r))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            header,
            transactions,
        })
    }
}

/// A header with every field zero except the given ones, for tests and
/// for the genesis block.
pub fn empty_header(height: u32, prev_hash: BlockHash, commitment_root: Anchor) -> BlockHeader {
    let version = BLOCK_VERSION;
    BlockHeader {
        version,
        prev_hash,
        height,
        timestamp: 0,
        commitment_root,
        nullifier_root: Anchor::from_base(crypto::pallas::Base::ZERO),
        state_root: Anchor::from_base(crypto::pallas::Base::ZERO),
        tx_root: tx_root([]),
        body_root: crate::body_tree::empty_body_root(),
        history_root: crate::header_tree::empty_root(),
        target: 0,
        nonce: [0; 32],
        solution: PowSolution::empty(),
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::TxId;
    use crypto::pallas;

    use super::*;

    fn anchor(v: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(v))
    }

    #[test]
    fn header_encodes_to_the_documented_length_and_roundtrips() {
        let header = empty_header(3, BlockHash::from_bytes([1; 32]), anchor(9));
        let bytes = header.to_vec();
        assert_eq!(bytes.len(), HEADER_LEN_V1);
        assert_eq!(header.encoded_len(), HEADER_LEN_V1);
        assert_eq!(BlockHeader::from_slice(&bytes), Ok(header));
    }

    #[test]
    fn genesis_keeps_the_v1_header_encoding_and_versioned_pow_domain() {
        let header = empty_header(0, BlockHash::ZERO, anchor(9));
        assert_eq!(header.version, BLOCK_VERSION);
        assert_eq!(header.to_vec().len(), HEADER_LEN_V1);
        assert_eq!(header.encoded_len(), HEADER_LEN_V1);
        assert_eq!(
            BlockHeader::from_slice(&header.to_vec()),
            Ok(header.clone())
        );
        assert!(header.pow_input().starts_with(b"Kryptos:RandomX:v1"));
        assert!(empty_header(1, BlockHash::ZERO, anchor(9))
            .pow_input()
            .starts_with(b"Kryptos:RandomX:v1"));
    }

    #[test]
    fn hash_and_pow_input_bind_the_nonce() {
        let base = empty_header(1, BlockHash::ZERO, anchor(1));
        let mut other = base.clone();
        other.nonce[0] = 1;
        assert_ne!(base.hash(), other.hash());
        assert_ne!(base.pow_input(), other.pow_input());
        assert_eq!(base.transition_hash(), other.transition_hash());
        other.timestamp = 5;
        assert_ne!(base.pow_input(), other.pow_input());
        assert_eq!(
            base.pow_input().len(),
            HEADER_LEN_V1 - POW_SOLUTION_LEN + b"Kryptos:RandomX:v1".len()
        );

        let mut other_solution = base.clone();
        other_solution.solution = PowSolution::from_bytes([1; POW_SOLUTION_LEN]);
        assert_ne!(base.hash(), other_solution.hash());
        assert_eq!(base.transition_hash(), other_solution.transition_hash());

        let transition = base.transition_hash();
        let mut changed_root = base.clone();
        changed_root.state_root = anchor(2);
        assert_ne!(transition, changed_root.transition_hash());
        let mut changed_prev = base.clone();
        changed_prev.prev_hash = BlockHash::from_bytes([1; 32]);
        assert_ne!(transition, changed_prev.transition_hash());
        let mut changed_tx_root = base.clone();
        changed_tx_root.tx_root[0] ^= 1;
        assert_ne!(transition, changed_tx_root.transition_hash());
        let mut changed_body_root = base.clone();
        changed_body_root.body_root[0] ^= 1;
        assert_ne!(transition, changed_body_root.transition_hash());
        let mut changed_history_root = base.clone();
        changed_history_root.history_root[0] ^= 1;
        assert_ne!(transition, changed_history_root.transition_hash());
    }

    #[test]
    fn empty_block_roundtrips_and_has_a_consistent_tx_root() {
        let block = Block::new(empty_header(0, BlockHash::ZERO, anchor(0)), Vec::new());
        assert_eq!(block.check_tx_root(), Ok(()));
        assert_eq!(Block::from_slice(&block.to_vec()), Ok(block.clone()));
        assert_eq!(block.hash(), block.header().hash());
        assert_eq!(block.transactions().len(), 0);
    }

    #[test]
    fn tx_root_mismatch_is_detected() {
        let mut header = empty_header(0, BlockHash::ZERO, anchor(0));
        header.tx_root = [7; 32];
        let block = Block::new(header, Vec::new());
        assert_eq!(
            block.check_tx_root(),
            Err(Error::InvalidBlock("transaction root mismatch"))
        );
    }

    #[test]
    fn v1_tx_merkle_root_binds_order_count_and_padding() {
        let a = TxId::from_bytes([1; 32]);
        let b = TxId::from_bytes([2; 32]);
        let c = TxId::from_bytes([3; 32]);
        let ab = tx_root([a, b]);
        assert_ne!(ab, tx_root([b, a]));
        assert_ne!(ab, tx_root([a, b, c]));
        assert_ne!(tx_root([]), tx_root([a]));
        assert_eq!(tx_root([a, b]), tx_root([a, b]));
        // The flat pre-Merkle commitment is distinct from the active root.
    }

    #[test]
    fn unknown_header_versions_are_rejected() {
        for version in [0, 2, 3, 99] {
            let mut bytes = empty_header(0, BlockHash::ZERO, anchor(0)).to_vec();
            bytes[0] = version;
            assert_eq!(
                BlockHeader::from_slice(&bytes),
                Err(Error::Malformed("unknown block header version"))
            );
        }
    }

    #[test]
    fn a_truncated_old_v1_layout_is_not_accepted_as_the_full_v1_header() {
        let header = empty_header(0, BlockHash::ZERO, anchor(0));
        let old_layout_len = HEADER_LEN_V1 - 4 * SHORT_OUTPUT_LEN;
        assert!(BlockHeader::from_slice(&header.to_vec()[..old_layout_len]).is_err());
    }

    #[test]
    fn oversized_transaction_count_is_rejected() {
        let mut bytes = empty_header(0, BlockHash::ZERO, anchor(0)).to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Block::from_slice(&bytes),
            Err(Error::InvalidBlock("too many transactions"))
        ));
    }

    #[test]
    fn block_hash_displays_as_hex() {
        let hash = BlockHash::from_bytes([0xab; 32]);
        assert_eq!(hash.to_string(), "ab".repeat(32));
        assert_eq!(
            format!("{hash:?}"),
            format!("BlockHash({})", "ab".repeat(32))
        );
        assert_eq!(
            format!("{:?}", PowSolution::empty()),
            format!("PowSolution({POW_SOLUTION_LEN} bytes)")
        );
    }
}
