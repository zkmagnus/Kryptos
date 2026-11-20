//! Ordered transaction-id Merkle commitments and bounded inclusion paths.
//!
//! These hashes define the v1 transaction-root format. The root commits to
//! each position and the transaction count, while proofs and signatures remain
//! outside txids. Complete authorization bytes belong to the body tree.

use crypto::hash::{blake2b_short, SHORT_OUTPUT_LEN, TX_ROOT};

use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::MAX_BLOCK_TRANSACTIONS;
use crate::transaction::TxId;
use crate::{Error, Result};

const PATH_VERSION: u8 = 1;

/// The transaction root over a list of transaction ids.
pub fn tx_root(txids: impl IntoIterator<Item = TxId>) -> [u8; SHORT_OUTPUT_LEN] {
    let txids: Vec<TxId> = txids.into_iter().collect();
    let count = u64::try_from(txids.len()).unwrap_or(u64::MAX);
    if txids.is_empty() {
        return tx_merkle_empty_root();
    }
    let width = txids.len().max(1).next_power_of_two();
    let mut level = Vec::with_capacity(width);
    for (index, txid) in txids.iter().enumerate() {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        level.push(tx_merkle_leaf(index, txid));
    }
    for index in txids.len()..width {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        level.push(tx_merkle_padding(index));
    }
    let mut tree_level = 0u32;
    while level.len() > 1 {
        let mut parents = Vec::with_capacity(level.len() / 2);
        for [left, right] in level.as_chunks::<2>().0 {
            parents.push(tx_merkle_node(tree_level, left, right));
        }
        level = parents;
        tree_level = tree_level.saturating_add(1);
    }
    let root = level.first().copied().unwrap_or([0; SHORT_OUTPUT_LEN]);
    tx_merkle_finalize(count, &root)
}

const TX_MERKLE_LEAF_TAG: &[u8] = b"Kryptos:TxMerkle:leaf:v1";
const TX_MERKLE_PAD_TAG: &[u8] = b"Kryptos:TxMerkle:pad:v1";
const TX_MERKLE_NODE_TAG: &[u8] = b"Kryptos:TxMerkle:node:v1";
const TX_MERKLE_ROOT_TAG: &[u8] = b"Kryptos:TxMerkle:root:v1";
const TX_MERKLE_EMPTY_TAG: &[u8] = b"Kryptos:TxMerkle:empty:v1";

fn tx_merkle_leaf(index: u64, txid: &TxId) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        TX_ROOT,
        &[TX_MERKLE_LEAF_TAG, &index.to_le_bytes(), txid.as_bytes()],
    )
}

fn tx_merkle_padding(index: u64) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(TX_ROOT, &[TX_MERKLE_PAD_TAG, &index.to_le_bytes()])
}

fn tx_merkle_node(
    level: u32,
    left: &[u8; SHORT_OUTPUT_LEN],
    right: &[u8; SHORT_OUTPUT_LEN],
) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        TX_ROOT,
        &[TX_MERKLE_NODE_TAG, &level.to_le_bytes(), left, right],
    )
}

fn tx_merkle_finalize(count: u64, root: &[u8; SHORT_OUTPUT_LEN]) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(TX_ROOT, &[TX_MERKLE_ROOT_TAG, &count.to_le_bytes(), root])
}

fn tx_merkle_empty_root() -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(TX_ROOT, &[TX_MERKLE_EMPTY_TAG, &0u64.to_le_bytes()])
}

/// An inclusion path for one transaction in a v1 block transaction root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMerklePath {
    index: u64,
    count: u64,
    siblings: Vec<[u8; SHORT_OUTPUT_LEN]>,
}

impl TxMerklePath {
    /// The transaction index in the block.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Number of transactions committed by the root.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Sibling subtree digests from the transaction level upward.
    pub fn siblings(&self) -> &[[u8; SHORT_OUTPUT_LEN]] {
        &self.siblings
    }

    /// Checks this path against a transaction id and v1 transaction root.
    pub fn verify(&self, txid: &TxId, expected_root: &[u8; SHORT_OUTPUT_LEN]) -> bool {
        let Ok(count_usize) = usize::try_from(self.count) else {
            return false;
        };
        if self.count == 0 || count_usize > MAX_BLOCK_TRANSACTIONS || self.index >= self.count {
            return false;
        }
        let Some(width) = count_usize.checked_next_power_of_two() else {
            return false;
        };
        let depth = usize::try_from(width.trailing_zeros()).unwrap_or(usize::MAX);
        if self.siblings.len() != depth {
            return false;
        }
        let mut node = tx_merkle_leaf(self.index, txid);
        for (level, sibling) in self.siblings.iter().enumerate() {
            let Ok(level) = u32::try_from(level) else {
                return false;
            };
            node = if (self.index >> level) & 1 == 0 {
                tx_merkle_node(level, &node, sibling)
            } else {
                tx_merkle_node(level, sibling, &node)
            };
        }
        &tx_merkle_finalize(self.count, &node) == expected_root
    }
}

impl Encodable for TxMerklePath {
    fn write(&self, writer: &mut Writer) {
        writer
            .put_u8(PATH_VERSION)
            .put_u64_le(self.index)
            .put_u64_le(self.count)
            .put_u8(u8::try_from(self.siblings.len()).unwrap_or(u8::MAX));
        for sibling in &self.siblings {
            writer.put(sibling);
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.take_u8()? != PATH_VERSION {
            return Err(Error::Malformed("transaction path version"));
        }
        let index = reader.take_u64_le()?;
        let count = reader.take_u64_le()?;
        let depth = usize::from(reader.take_u8()?);
        let count_usize =
            usize::try_from(count).map_err(|_| Error::Malformed("transaction path count"))?;
        if count_usize == 0 || count_usize > MAX_BLOCK_TRANSACTIONS || index >= count {
            return Err(Error::Malformed("transaction path metadata"));
        }
        let width = count_usize
            .checked_next_power_of_two()
            .ok_or(Error::Malformed("transaction path width"))?;
        if u32::try_from(depth).ok() != Some(width.trailing_zeros()) {
            return Err(Error::Malformed("transaction path depth"));
        }
        let sibling_bytes = depth
            .checked_mul(SHORT_OUTPUT_LEN)
            .ok_or(Error::Malformed("transaction path size"))?;
        if reader.remaining() < sibling_bytes {
            return Err(Error::Malformed("truncated transaction path"));
        }
        let siblings = (0..depth)
            .map(|_| reader.take_array())
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
}

/// Builds a v1 block transaction inclusion path at `index`.
pub fn tx_merkle_path(txids: &[TxId], index: usize) -> Option<TxMerklePath> {
    if txids.is_empty() || txids.len() > MAX_BLOCK_TRANSACTIONS || index >= txids.len() {
        return None;
    }
    let count = u64::try_from(txids.len()).ok()?;
    let index = u64::try_from(index).ok()?;
    let width = txids.len().checked_next_power_of_two()?;
    let mut level = Vec::with_capacity(width);
    for (position, id) in txids.iter().enumerate() {
        let position = u64::try_from(position).ok()?;
        level.push(tx_merkle_leaf(position, id));
    }
    for position in txids.len()..width {
        level.push(tx_merkle_padding(u64::try_from(position).ok()?));
    }

    let mut path_index = usize::try_from(index).ok()?;
    let mut level_number = 0u32;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        siblings.push(*level.get(path_index ^ 1)?);
        let mut parents = Vec::with_capacity(level.len() / 2);
        for [left, right] in level.as_chunks::<2>().0 {
            parents.push(tx_merkle_node(level_number, left, right));
        }
        level = parents;
        path_index /= 2;
        level_number = level_number.checked_add(1)?;
    }
    Some(TxMerklePath {
        index,
        count,
        siblings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_paths_roundtrip_with_bounded_canonical_metadata() {
        for count in [1, 2, 3, 5, MAX_BLOCK_TRANSACTIONS] {
            let ids = (0..count)
                .map(|position| {
                    let mut bytes = [0; 32];
                    bytes[..8].copy_from_slice(&(position as u64).to_le_bytes());
                    TxId::from_bytes(bytes)
                })
                .collect::<Vec<_>>();
            for position in [0, count - 1] {
                let path = tx_merkle_path(&ids, position).unwrap();
                assert_eq!(TxMerklePath::from_slice(&path.to_vec()), Ok(path.clone()));
                assert!(path.verify(&ids[position], &tx_root(ids.iter().copied())));
            }
        }
    }

    #[test]
    fn transaction_path_parser_rejects_malformed_counts_indices_and_depths() {
        let ids = [TxId::from_bytes([3; 32]); 3];
        let bytes = tx_merkle_path(&ids, 1).unwrap().to_vec();
        let mut wrong_version = bytes.clone();
        wrong_version[0] = u8::MAX;
        assert!(TxMerklePath::from_slice(&wrong_version).is_err());
        let mut wrong_count = bytes.clone();
        wrong_count[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(TxMerklePath::from_slice(&wrong_count).is_err());
        let mut zero_count = bytes.clone();
        zero_count[9..17].copy_from_slice(&0u64.to_le_bytes());
        assert!(TxMerklePath::from_slice(&zero_count).is_err());
        let mut wrong_index = bytes.clone();
        wrong_index[1..9].copy_from_slice(&3u64.to_le_bytes());
        assert!(TxMerklePath::from_slice(&wrong_index).is_err());
        let mut wrong_depth = bytes.clone();
        wrong_depth[17] = u8::MAX;
        assert!(TxMerklePath::from_slice(&wrong_depth).is_err());
        assert!(TxMerklePath::from_slice(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(TxMerklePath::from_slice(&trailing).is_err());
        let oversized = [TxId::from_bytes([1; 32]); MAX_BLOCK_TRANSACTIONS + 1];
        assert!(tx_merkle_path(&oversized, 0).is_none());
    }

    #[test]
    fn tx_merkle_paths_verify_for_non_power_of_two_lists_and_bind_metadata() {
        let txids = [
            TxId::from_bytes([1; 32]),
            TxId::from_bytes([2; 32]),
            TxId::from_bytes([3; 32]),
            TxId::from_bytes([4; 32]),
            TxId::from_bytes([5; 32]),
        ];
        let root = tx_root(txids);
        for index in 0..txids.len() {
            let path = tx_merkle_path(&txids, index).unwrap();
            assert_eq!(path.index(), index as u64);
            assert_eq!(path.count(), txids.len() as u64);
            assert!(path.verify(&txids[index], &root));

            let mut wrong_index = path.clone();
            wrong_index.index += 1;
            assert!(!wrong_index.verify(&txids[index], &root));

            let mut wrong_count = path.clone();
            wrong_count.count += 1;
            assert!(!wrong_count.verify(&txids[index], &root));

            let mut wrong_sibling = path.clone();
            wrong_sibling.siblings[0][0] ^= 1;
            assert!(!wrong_sibling.verify(&txids[index], &root));
        }
        assert!(tx_merkle_path(&txids, txids.len()).is_none());
        assert!(tx_merkle_path(&[], 0).is_none());
        assert!(!tx_merkle_path(&txids, 0)
            .unwrap()
            .verify(&TxId::from_bytes([8; 32]), &root));
    }
}
