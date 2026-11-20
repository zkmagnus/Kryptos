//! Merkle commitments to a block's complete canonical body.
//!
//! The body is `u32_le(transaction_count) || transaction_encodings`; it excludes
//! the header. Unlike the transaction-id tree, this commitment includes every
//! proof and signature byte. A chunk path authenticates bytes to a known root;
//! it does not validate transactions or establish that the root is canonical.

use crypto::hash::{blake2b_short, BLOCK_BODY, SHORT_OUTPUT_LEN};

use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{
    proof_len, COINBASE_KIND, MAX_ACTIONS, MAX_BLOCK_TRANSACTIONS, TRANSFER_KIND, TX_VERSION,
};
use crate::transaction::Transaction;
use crate::{Error, Result};

/// Number of bytes in a full body chunk. Only the final chunk may be shorter.
pub const BODY_CHUNK_SIZE: usize = 64 * 1024;
/// Version of the canonical body-byte Merkle commitment.
pub const BODY_TREE_VERSION: u8 = 1;

const BODY_PATH_VERSION: u8 = 1;
const LEAF_TAG: &[u8] = b"Kryptos:BodyMerkle:leaf:v1";
const PAD_TAG: &[u8] = b"Kryptos:BodyMerkle:pad:v1";
const NODE_TAG: &[u8] = b"Kryptos:BodyMerkle:node:v1";
const ROOT_TAG: &[u8] = b"Kryptos:BodyMerkle:root:v1";
const COUNT_LEN: usize = core::mem::size_of::<u32>();

type Digest = [u8; SHORT_OUTPUT_LEN];

/// Largest body encoding permitted by the transaction-count and action limits.
///
/// # Errors
/// Returns an error if those configured limits cannot be represented.
pub fn max_body_len() -> Result<usize> {
    MAX_BLOCK_TRANSACTIONS
        .checked_mul(Transaction::encoded_len_for_actions(MAX_ACTIONS)?)
        .and_then(|len| len.checked_add(COUNT_LEN))
        .ok_or(Error::Malformed("body size overflow"))
}

/// Serializes the canonical body, excluding the block header.
///
/// This checks encoding shape and bounds, including action classes and proof
/// lengths. It does not check signatures, proofs, coinbase position or state.
/// A zero-transaction body is encodable for genesis compatibility.
///
/// # Errors
/// Rejects excessive counts and non-canonical transaction encoding shapes.
pub fn body_bytes(transactions: &[Transaction]) -> Result<Vec<u8>> {
    if transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(Error::InvalidBlock("too many transactions"));
    }
    let count = u32::try_from(transactions.len())
        .map_err(|_| Error::Malformed("body transaction count"))?;
    let mut len = COUNT_LEN;
    for transaction in transactions {
        if transaction.version() != TX_VERSION
            || (transaction.kind() != TRANSFER_KIND && transaction.kind() != COINBASE_KIND)
            || transaction.proof().as_bytes().len() != proof_len(transaction.actions().len())?
        {
            return Err(Error::Malformed("body transaction encoding"));
        }
        len = len
            .checked_add(Transaction::encoded_len_for_actions(
                transaction.actions().len(),
            )?)
            .ok_or(Error::Malformed("body size overflow"))?;
    }
    if len > max_body_len()? {
        return Err(Error::InvalidBlock("body too large"));
    }
    let mut writer = Writer::with_capacity(len);
    writer.put(&count.to_le_bytes());
    for transaction in transactions {
        transaction.write(&mut writer);
    }
    let bytes = writer.into_bytes();
    if bytes.len() != len {
        return Err(Error::Malformed("body encoding length mismatch"));
    }
    Ok(bytes)
}

/// Commits to every byte of the complete canonical transaction body.
///
/// # Errors
/// Propagates the body encoding and size checks from [`body_bytes`].
pub fn body_root(transactions: &[Transaction]) -> Result<Digest> {
    body_root_from_bytes(&body_bytes(transactions)?)
}

/// Root for the canonical empty body (`LE32(0)`).
pub fn empty_body_root() -> Digest {
    let count = 1;
    let node = leaf(0, &0u32.to_le_bytes());
    finalize(COUNT_LEN as u64, count, &node)
}

/// Commits to a length-bounded body byte string.
///
/// Callers receiving a complete body must also parse its transactions and
/// validate them. This function only enforces the body byte-length bounds;
/// it does not interpret the transaction-count prefix or transaction contents.
///
/// # Errors
/// Rejects bodies shorter than the count prefix or beyond [`max_body_len`].
pub fn body_root_from_bytes(body: &[u8]) -> Result<Digest> {
    let (count, mut nodes) = leaves(body)?;
    let mut level = 0u32;
    while nodes.len() > 1 {
        nodes = parent_level(&nodes, level);
        level += 1;
    }
    let node = nodes.first().ok_or(Error::Malformed("empty body tree"))?;
    Ok(finalize(
        u64::try_from(body.len()).map_err(|_| Error::Malformed("body size overflow"))?,
        count,
        node,
    ))
}

/// An inclusion proof for one byte chunk in a complete block body.
///
/// The root binds byte length, chunk count and fixed chunk size. Parsing checks
/// all metadata and the exact path depth before allocating sibling storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyMerklePath {
    index: u32,
    count: u32,
    body_len: u64,
    siblings: Vec<Digest>,
}

impl BodyMerklePath {
    /// Zero-based chunk position in the body.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Number of chunks in the committed body.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Exact byte length of the committed body.
    pub fn body_len(&self) -> u64 {
        self.body_len
    }

    /// Sibling digests from the leaf level upward.
    pub fn siblings(&self) -> &[Digest] {
        &self.siblings
    }

    /// Checks a chunk against a root authenticated by the caller.
    ///
    /// Chunks at the wrong index or with a non-canonical length fail. This
    /// verifies byte inclusion only; authorization and chain validity require
    /// the ordinary block-validation path.
    pub fn verify(&self, chunk: &[u8], expected_root: &Digest) -> bool {
        let Ok(depth) = path_depth(self.index, self.count, self.body_len) else {
            return false;
        };
        if self.siblings.len() != depth {
            return false;
        }
        let offset = u64::from(self.index) * BODY_CHUNK_SIZE as u64;
        let expected_len = (self.body_len - offset).min(BODY_CHUNK_SIZE as u64);
        if u64::try_from(chunk.len()).ok() != Some(expected_len) {
            return false;
        }
        let mut node = leaf(self.index, chunk);
        for (level, sibling) in self.siblings.iter().enumerate() {
            let Ok(level) = u32::try_from(level) else {
                return false;
            };
            node = if (self.index >> level) & 1 == 0 {
                branch(level, &node, sibling)
            } else {
                branch(level, sibling, &node)
            };
        }
        &finalize(self.body_len, self.count, &node) == expected_root
    }
}

impl Encodable for BodyMerklePath {
    fn write(&self, writer: &mut Writer) {
        writer
            .put_u8(BODY_PATH_VERSION)
            .put(&self.index.to_le_bytes())
            .put(&self.count.to_le_bytes())
            .put_u64_le(self.body_len)
            .put_u8(u8::try_from(self.siblings.len()).unwrap_or(u8::MAX));
        for sibling in &self.siblings {
            writer.put(sibling);
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.take_u8()? != BODY_PATH_VERSION {
            return Err(Error::Malformed("body path version"));
        }
        let index = u32::from_le_bytes(reader.take_array()?);
        let count = u32::from_le_bytes(reader.take_array()?);
        let body_len = reader.take_u64_le()?;
        let depth = usize::from(reader.take_u8()?);
        if path_depth(index, count, body_len)? != depth {
            return Err(Error::Malformed("body path depth"));
        }
        let sibling_bytes = depth
            .checked_mul(SHORT_OUTPUT_LEN)
            .ok_or(Error::Malformed("body path size"))?;
        if reader.remaining() < sibling_bytes {
            return Err(Error::Malformed("truncated body path"));
        }
        let siblings = (0..depth)
            .map(|_| reader.take_array())
            .collect::<Result<Vec<Digest>>>()?;
        Ok(Self {
            index,
            count,
            body_len,
            siblings,
        })
    }
}

/// Builds an inclusion path for a chunk of a length-bounded body byte string.
///
/// # Errors
/// Rejects an invalid body length or an index outside its chunk range.
pub fn body_merkle_path(body: &[u8], index: usize) -> Result<BodyMerklePath> {
    let (count, mut nodes) = leaves(body)?;
    let index = u32::try_from(index).map_err(|_| Error::Malformed("body chunk index"))?;
    let body_len = u64::try_from(body.len()).map_err(|_| Error::Malformed("body size overflow"))?;
    let depth = path_depth(index, count, body_len)?;
    let mut position = usize::try_from(index).map_err(|_| Error::Malformed("body chunk index"))?;
    let mut siblings = Vec::with_capacity(depth);
    let mut level = 0u32;
    while nodes.len() > 1 {
        siblings.push(
            *nodes
                .get(position ^ 1)
                .ok_or(Error::Malformed("body sibling index"))?,
        );
        nodes = parent_level(&nodes, level);
        position /= 2;
        level += 1;
    }
    Ok(BodyMerklePath {
        index,
        count,
        body_len,
        siblings,
    })
}

fn path_depth(index: u32, count: u32, body_len: u64) -> Result<usize> {
    let len = usize::try_from(body_len).map_err(|_| Error::Malformed("body size overflow"))?;
    let expected_count = chunk_count(len)?;
    if count != expected_count || index >= count {
        return Err(Error::Malformed("body path chunk metadata"));
    }
    let width = count
        .checked_next_power_of_two()
        .ok_or(Error::Malformed("body tree width"))?;
    usize::try_from(width.trailing_zeros()).map_err(|_| Error::Malformed("body path depth"))
}

fn chunk_count(len: usize) -> Result<u32> {
    if len < COUNT_LEN || len > max_body_len()? {
        return Err(Error::Malformed("body byte length"));
    }
    u32::try_from(len.div_ceil(BODY_CHUNK_SIZE)).map_err(|_| Error::Malformed("body chunk count"))
}

fn leaves(body: &[u8]) -> Result<(u32, Vec<Digest>)> {
    let count = chunk_count(body.len())?;
    let width = usize::try_from(
        count
            .checked_next_power_of_two()
            .ok_or(Error::Malformed("body tree width"))?,
    )
    .map_err(|_| Error::Malformed("body tree width"))?;
    let mut nodes = Vec::with_capacity(width);
    for (index, chunk) in body.chunks(BODY_CHUNK_SIZE).enumerate() {
        nodes.push(leaf(
            u32::try_from(index).map_err(|_| Error::Malformed("body chunk index"))?,
            chunk,
        ));
    }
    for index in nodes.len()..width {
        let index = u32::try_from(index).map_err(|_| Error::Malformed("body padding index"))?;
        nodes.push(blake2b_short(BLOCK_BODY, &[PAD_TAG, &index.to_le_bytes()]));
    }
    Ok((count, nodes))
}

fn parent_level(nodes: &[Digest], level: u32) -> Vec<Digest> {
    nodes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[left, right]| branch(level, left, right))
        .collect()
}

fn leaf(index: u32, chunk: &[u8]) -> Digest {
    blake2b_short(
        BLOCK_BODY,
        &[
            LEAF_TAG,
            &index.to_le_bytes(),
            &(chunk.len() as u64).to_le_bytes(),
            chunk,
        ],
    )
}

fn branch(level: u32, left: &Digest, right: &Digest) -> Digest {
    blake2b_short(BLOCK_BODY, &[NODE_TAG, &level.to_le_bytes(), left, right])
}

fn finalize(body_len: u64, count: u32, root: &Digest) -> Digest {
    blake2b_short(
        BLOCK_BODY,
        &[
            ROOT_TAG,
            &body_len.to_le_bytes(),
            &count.to_le_bytes(),
            &(BODY_CHUNK_SIZE as u64).to_le_bytes(),
            root,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::tests::sample_transaction;

    #[test]
    fn authorization_bytes_change_body_root_without_changing_tx_root() {
        let transaction = sample_transaction(73, 2);
        let original_tx_root = crate::block::tx_root([transaction.txid()]);
        let original_body_root = body_root(core::slice::from_ref(&transaction)).unwrap();

        for offset_from_end in [1, crypto::signature::SIGNATURE_LEN + 1] {
            let mut encoding = transaction.to_vec();
            let offset = encoding.len() - offset_from_end;
            encoding[offset] ^= 1; // binding signature, then final proof byte
            let altered = Transaction::from_slice(&encoding).unwrap();
            assert_eq!(crate::block::tx_root([altered.txid()]), original_tx_root);
            assert_ne!(body_root(&[altered]).unwrap(), original_body_root);
        }
    }

    #[test]
    fn transaction_body_preserves_the_existing_count_and_transaction_encoding() {
        let transactions = [sample_transaction(74, 2), sample_transaction(75, 4)];
        let body = body_bytes(&transactions).unwrap();
        let mut reader = Reader::new(&body);
        assert_eq!(u32::from_le_bytes(reader.take_array().unwrap()), 2);
        for transaction in transactions {
            assert_eq!(Transaction::read(&mut reader).unwrap(), transaction);
        }
        reader.finish().unwrap();
    }

    #[test]
    fn count_only_body_is_committed_and_has_a_zero_depth_path() {
        let bytes = body_bytes(&[]).unwrap();
        assert_eq!(bytes, 0u32.to_le_bytes());
        let root = body_root(&[]).unwrap();
        assert_eq!(root, body_root_from_bytes(&bytes).unwrap());
        let path = body_merkle_path(&bytes, 0).unwrap();
        assert_eq!(path.count(), 1);
        assert!(path.siblings().is_empty());
        assert!(path.verify(&bytes, &root));
        assert!(!path.verify(&[0; COUNT_LEN - 1], &root));
    }

    #[test]
    fn non_power_of_two_body_authenticates_each_chunk_and_roundtrips_paths() {
        let body = (0..2 * BODY_CHUNK_SIZE + 17)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let root = body_root_from_bytes(&body).unwrap();
        for (index, chunk) in body.chunks(BODY_CHUNK_SIZE).enumerate() {
            let path = body_merkle_path(&body, index).unwrap();
            assert_eq!(path.count(), 3);
            assert_eq!(path.siblings().len(), 2);
            assert!(path.verify(chunk, &root));
            assert_eq!(BodyMerklePath::from_slice(&path.to_vec()), Ok(path.clone()));
            let mut changed = chunk.to_vec();
            changed[0] ^= 1;
            assert!(!path.verify(&changed, &root));
        }
        assert!(body_merkle_path(&body, 3).is_err());
    }

    #[test]
    fn length_order_index_and_path_metadata_are_bound() {
        let mut body = vec![7; BODY_CHUNK_SIZE];
        body.extend_from_slice(&[8; BODY_CHUNK_SIZE]);
        body.extend_from_slice(&[9; 17]);
        let root = body_root_from_bytes(&body).unwrap();
        let path = body_merkle_path(&body, 1).unwrap();
        let chunk = &body[BODY_CHUNK_SIZE..2 * BODY_CHUNK_SIZE];
        assert!(path.verify(chunk, &root));

        let mut changed_index = path.clone();
        changed_index.index = 0;
        assert!(!changed_index.verify(chunk, &root));
        let mut changed_count = path.clone();
        changed_count.count += 1;
        assert!(!changed_count.verify(chunk, &root));
        let mut changed_len = path.clone();
        changed_len.body_len += 1;
        assert!(!changed_len.verify(chunk, &root));
        let mut changed_path = path.clone();
        changed_path.siblings[0][0] ^= 1;
        assert!(!changed_path.verify(chunk, &root));
        assert!(!path.verify(&chunk[..chunk.len() - 1], &root));

        body.swap(0, BODY_CHUNK_SIZE);
        assert_ne!(body_root_from_bytes(&body).unwrap(), root);
        assert_ne!(body_root_from_bytes(&body[..body.len() - 1]).unwrap(), root);
    }

    #[test]
    fn path_parser_rejects_bad_metadata_before_sibling_allocation() {
        let body = vec![4; BODY_CHUNK_SIZE + 1];
        let encoded = body_merkle_path(&body, 0).unwrap().to_vec();
        assert!(BodyMerklePath::from_slice(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(BodyMerklePath::from_slice(&trailing).is_err());
        let mut wrong_depth = encoded.clone();
        wrong_depth[17] = u8::MAX;
        assert!(BodyMerklePath::from_slice(&wrong_depth).is_err());
        let mut huge_len = encoded.clone();
        huge_len[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(BodyMerklePath::from_slice(&huge_len).is_err());
        let mut huge_count = encoded;
        huge_count[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(BodyMerklePath::from_slice(&huge_count).is_err());
        assert!(body_root_from_bytes(&[]).is_err());
        assert!(body_root_from_bytes(&[0; COUNT_LEN - 1]).is_err());
    }
}
