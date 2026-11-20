//! Append-only Merkle Mountain Range commitments to headers by block height.
//!
//! A child header commits to the frontier through its parent. Appending the
//! child happens after its full header hash is known, avoiding a self-reference.
//! These commitments prove inclusion; header rules, proof of work, fork choice,
//! and transaction validity remain separate checks.

use crypto::hash::{blake2b_short, HEADER_TREE};

use crate::block::{BlockHash, BlockHeader};
use crate::bytes::{Encodable, Reader, Writer};
use crate::{Error, Result};

/// Maximum mountain height and number of bits in a block height.
pub const HEADER_TREE_DEPTH: usize = 32;
/// Version of the append-only MMR commitment carried by v1 headers.
pub const HEADER_TREE_COMMITMENT_VERSION: u8 = 1;
/// Maximum number of headers, including genesis, in one header history.
pub const HEADER_TREE_CAPACITY: u64 = 1u64 << HEADER_TREE_DEPTH;
/// Maximum byte length of a canonical frontier encoding.
pub const HEADER_FRONTIER_MAX_LEN: usize = 1 + 8 + 32 + HEADER_TREE_DEPTH * 32;
/// Maximum byte length of a canonical MMR path encoding.
pub const HEADER_MERKLE_PATH_MAX_LEN: usize = 1 + 4 + 8 + 1 + (2 * HEADER_TREE_DEPTH - 2) * 32;

/// One header-tree digest.
pub type HeaderDigest = [u8; 32];
/// Content-addressed internal node: `(digest, left, right)`.
pub type HeaderNode = (HeaderDigest, HeaderDigest, HeaderDigest);

const HEADER_TREE_ENCODING_VERSION: u8 = 1;
const LEAF_TAG: &[u8] = b"Kryptos:HeaderMMR:leaf:v1";
const NODE_TAG: &[u8] = b"Kryptos:HeaderMMR:node:v1";
const ROOT_TAG: &[u8] = b"Kryptos:HeaderMMR:root:v1";

/// Commits a header hash at its exact block height.
pub fn header_leaf(height: u32, hash: &BlockHash) -> HeaderDigest {
    blake2b_short(
        HEADER_TREE,
        &[LEAF_TAG, &height.to_le_bytes(), hash.as_bytes()],
    )
}

/// Commits two child nodes at `level`, where level zero combines leaves.
pub fn header_node(level: u32, left: &HeaderDigest, right: &HeaderDigest) -> HeaderDigest {
    blake2b_short(HEADER_TREE, &[NODE_TAG, &level.to_le_bytes(), left, right])
}

/// Returns the canonical left-to-right mountain `(start, level)` containing
/// `index`, or `None` if `index` is outside the committed prefix.
pub fn mountain_for_index(index: u32, count: u64) -> Option<(u64, u32)> {
    if count == 0 || count > HEADER_TREE_CAPACITY || u64::from(index) >= count {
        return None;
    }
    let index = u64::from(index);
    let mut start = 0u64;
    for level in (0..=HEADER_TREE_DEPTH).rev() {
        if (count >> level) & 1 != 0 {
            let width = 1u64 << level;
            let end = start.checked_add(width)?;
            if index < end {
                return Some((start, u32::try_from(level).ok()?));
            }
            start = end;
        }
    }
    None
}

/// Binds the count, maximum depth, and canonical left-to-right peak list.
///
/// Peak levels must be the set bits of `count`, in descending order. Builders
/// and proof parsers validate this; this helper is a domain-separated hash
/// primitive and does not validate the list on its own.
fn finalize_root(count: u64, peaks: &[(u32, HeaderDigest)]) -> HeaderDigest {
    let count_bytes = count.to_le_bytes();
    let depth_bytes = (HEADER_TREE_DEPTH as u32).to_le_bytes();
    let peak_count = u32::try_from(peaks.len()).unwrap_or(u32::MAX).to_le_bytes();
    let mut state = Vec::with_capacity(1 + 8 + 4 + 4 + peaks.len() * 36);
    state.extend_from_slice(ROOT_TAG);
    state.extend_from_slice(&depth_bytes);
    state.extend_from_slice(&count_bytes);
    state.extend_from_slice(&peak_count);
    for (level, digest) in peaks {
        state.extend_from_slice(&level.to_le_bytes());
        state.extend_from_slice(digest);
    }
    blake2b_short(HEADER_TREE, &[&state])
}

/// The count-bound commitment to an empty header history.
pub fn empty_root() -> HeaderDigest {
    finalize_root(0, &[])
}

/// Compact append state for one branch's contiguous header history.
///
/// A peak at level `i` is present exactly when bit `i` of `count` is set.
/// Level 32 supports the final header at height `u32::MAX`. The frontier
/// stores only peaks; persist the carry nodes returned by [`Self::append`]
/// to serve inclusion paths within complete mountains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFrontier {
    count: u64,
    tip_hash: BlockHash,
    peaks: [Option<HeaderDigest>; HEADER_TREE_DEPTH + 1],
}

impl Default for HeaderFrontier {
    fn default() -> Self {
        Self::empty()
    }
}

impl HeaderFrontier {
    /// An empty history, before genesis has been appended.
    pub fn empty() -> Self {
        Self {
            count: 0,
            tip_hash: BlockHash::ZERO,
            peaks: [None; HEADER_TREE_DEPTH + 1],
        }
    }

    /// Number of headers already appended, including genesis.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Hash of the most recently appended header, or `None` before genesis.
    pub fn tip_hash(&self) -> Option<BlockHash> {
        (self.count != 0).then_some(self.tip_hash)
    }

    /// Canonical left-to-right MMR peaks, ordered by descending level.
    pub fn peaks(&self) -> Vec<(u32, HeaderDigest)> {
        self.peaks
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(level, peak)| {
                peak.map(|digest| (u32::try_from(level).unwrap_or(u32::MAX), digest))
            })
            .collect()
    }

    /// Count/depth/peak-bound root of this branch's header history.
    pub fn root(&self) -> HeaderDigest {
        finalize_root(self.count, &self.peaks())
    }

    /// Appends the next header and returns only completed carry nodes for
    /// content-addressed storage.
    ///
    /// # Errors
    /// Refuses a full tree, a skipped/repeated height, or a different parent.
    /// Header rules, proof of work, and body validation are the caller's job.
    pub fn append(&mut self, header: &BlockHeader) -> Result<Vec<HeaderNode>> {
        if self.count >= HEADER_TREE_CAPACITY {
            return Err(Error::HeightExhausted);
        }
        if u64::from(header.height) != self.count {
            return Err(Error::InvalidBlock("header tree height is not consecutive"));
        }
        if header.prev_hash != self.tip_hash {
            return Err(Error::InvalidBlock("header tree parent mismatch"));
        }

        let hash = header.hash();
        let mut node = header_leaf(header.height, &hash);
        let mut level = 0;
        let mut nodes = Vec::with_capacity(HEADER_TREE_DEPTH);
        while (self.count >> level) & 1 != 0 {
            let left = self.peaks[level]
                .take()
                .ok_or(Error::InvalidBlock("header tree frontier is incomplete"))?;
            let parent = header_node(level as u32, &left, &node);
            nodes.push((parent, left, node));
            node = parent;
            level += 1;
        }
        self.peaks[level] = Some(node);
        self.count += 1;
        self.tip_hash = hash;
        Ok(nodes)
    }
}

impl Encodable for HeaderFrontier {
    fn write(&self, w: &mut Writer) {
        w.put_u8(HEADER_TREE_ENCODING_VERSION)
            .put_u64_le(self.count)
            .put(self.tip_hash.as_bytes());
        for (_, peak) in self.peaks() {
            w.put(&peak);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.take_u8()? != HEADER_TREE_ENCODING_VERSION {
            return Err(Error::Malformed("unknown header frontier version"));
        }
        let count = r.take_u64_le()?;
        if count > HEADER_TREE_CAPACITY {
            return Err(Error::Malformed("header frontier count exceeds capacity"));
        }
        let tip_hash = BlockHash::from_bytes(r.take_array()?);
        if count == 0 && tip_hash != BlockHash::ZERO {
            return Err(Error::Malformed("nonzero empty header frontier tip"));
        }
        let mut peaks = [None; HEADER_TREE_DEPTH + 1];
        for level in (0..=HEADER_TREE_DEPTH).rev() {
            if (count >> level) & 1 != 0 {
                peaks[level] = Some(r.take_array()?);
            }
        }
        Ok(Self {
            count,
            tip_hash,
            peaks,
        })
    }
}

/// An inclusion path for one header in a count-bound MMR root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderMerklePath {
    index: u32,
    count: u64,
    peak_level: u32,
    siblings: Vec<HeaderDigest>,
    /// Other peaks in canonical left-to-right order, excluding the selected one.
    other_peaks: Vec<(u32, HeaderDigest)>,
}

impl HeaderMerklePath {
    /// Constructs an MMR path after validating the selected mountain and peak order.
    ///
    /// # Errors
    /// Rejects an absent height, excessive count, incorrect path depth, or
    /// non-canonical other-peak levels.
    pub fn from_parts(
        index: u32,
        count: u64,
        peak_level: u32,
        siblings: Vec<HeaderDigest>,
        other_peaks: Vec<(u32, HeaderDigest)>,
    ) -> Result<Self> {
        let Some((start, expected_level)) = mountain_for_index(index, count) else {
            return Err(Error::Malformed("header path index or count"));
        };
        if peak_level != expected_level || siblings.len() != peak_level as usize {
            return Err(Error::Malformed("header path mountain depth"));
        }
        let expected_levels = peak_levels(count)
            .into_iter()
            .filter(|level| *level != peak_level)
            .collect::<Vec<_>>();
        if other_peaks.len() != expected_levels.len()
            || other_peaks
                .iter()
                .map(|(level, _)| *level)
                .ne(expected_levels.iter().copied())
        {
            return Err(Error::Malformed("header path peak ordering"));
        }
        let _ = start;
        Ok(Self {
            index,
            count,
            peak_level,
            siblings,
            other_peaks,
        })
    }

    /// Header height authenticated by the path.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Number of headers included in the authenticated root.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Selected mountain's level.
    pub fn peak_level(&self) -> u32 {
        self.peak_level
    }

    /// Sibling subtree digests from leaves to the selected mountain peak.
    pub fn siblings(&self) -> &[HeaderDigest] {
        &self.siblings
    }

    /// Other peaks in canonical left-to-right order, excluding the selected one.
    pub fn other_peaks(&self) -> &[(u32, HeaderDigest)] {
        &self.other_peaks
    }

    /// Checks height/hash inclusion against an independently authenticated root.
    ///
    /// This does not validate proof of work, ancestry, selected-chain status,
    /// transactions, or state transitions.
    pub fn verify(&self, header: &BlockHeader, expected_root: &HeaderDigest) -> bool {
        if header.height != self.index {
            return false;
        }
        let Some((start, level)) = mountain_for_index(self.index, self.count) else {
            return false;
        };
        if level != self.peak_level {
            return false;
        }
        let mut peak = header_leaf(self.index, &header.hash());
        let local_index = u64::from(self.index) - start;
        for (level, sibling) in self.siblings.iter().enumerate() {
            peak = if (local_index >> level) & 1 == 0 {
                header_node(level as u32, &peak, sibling)
            } else {
                header_node(level as u32, sibling, &peak)
            };
        }
        let mut peaks = Vec::with_capacity(self.other_peaks.len() + 1);
        let mut other = self.other_peaks.iter();
        let mut selected = false;
        for peak_level in peak_levels(self.count) {
            if peak_level == self.peak_level {
                peaks.push((peak_level, peak));
                selected = true;
            } else if let Some(value) = other.next() {
                if value.0 != peak_level {
                    return false;
                }
                peaks.push(*value);
            } else {
                return false;
            }
        }
        selected && other.next().is_none() && finalize_root(self.count, &peaks) == *expected_root
    }
}

impl Encodable for HeaderMerklePath {
    fn write(&self, w: &mut Writer) {
        w.put_u8(HEADER_TREE_ENCODING_VERSION)
            .put(&self.index.to_le_bytes())
            .put_u64_le(self.count)
            .put_u8(u8::try_from(self.peak_level).unwrap_or(u8::MAX));
        for sibling in &self.siblings {
            w.put(sibling);
        }
        for (_, peak) in &self.other_peaks {
            w.put(peak);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.take_u8()? != HEADER_TREE_ENCODING_VERSION {
            return Err(Error::Malformed("unknown header path version"));
        }
        let index = u32::from_le_bytes(r.take_array()?);
        let count = r.take_u64_le()?;
        let peak_level = u32::from(r.take_u8()?);
        let Some((_, expected_level)) = mountain_for_index(index, count) else {
            return Err(Error::Malformed("header path index or count"));
        };
        if peak_level != expected_level {
            return Err(Error::Malformed("header path mountain depth"));
        }
        let mut siblings = Vec::with_capacity(peak_level as usize);
        for _ in 0..peak_level {
            siblings.push(r.take_array()?);
        }
        let other_levels = peak_levels(count)
            .into_iter()
            .filter(|level| *level != peak_level)
            .collect::<Vec<_>>();
        let mut other_peaks = Vec::with_capacity(other_levels.len());
        for level in other_levels {
            other_peaks.push((level, r.take_array()?));
        }
        Self::from_parts(index, count, peak_level, siblings, other_peaks)
    }
}

fn peak_levels(count: u64) -> Vec<u32> {
    (0..=HEADER_TREE_DEPTH)
        .rev()
        .filter(|level| (count >> level) & 1 != 0)
        .filter_map(|level| u32::try_from(level).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crypto::pallas;

    use crate::block::empty_header;
    use crate::transaction::Anchor;

    use super::*;

    fn make_headers(count: u32) -> Vec<BlockHeader> {
        let mut parent = BlockHash::ZERO;
        (0..count)
            .map(|height| {
                let header = empty_header(height, parent, Anchor::from_base(pallas::Base::zero()));
                parent = header.hash();
                header
            })
            .collect()
    }

    fn nodes_for(headers: &[BlockHeader]) -> BTreeMap<HeaderDigest, (HeaderDigest, HeaderDigest)> {
        let mut frontier = HeaderFrontier::empty();
        let mut nodes = BTreeMap::new();
        for header in headers {
            for (hash, left, right) in frontier.append(header).unwrap() {
                nodes.insert(hash, (left, right));
            }
        }
        nodes
    }

    fn path_for(
        frontier: &HeaderFrontier,
        nodes: &BTreeMap<HeaderDigest, (HeaderDigest, HeaderDigest)>,
        index: u32,
    ) -> HeaderMerklePath {
        let (start, level) = mountain_for_index(index, frontier.count()).unwrap();
        let peaks = frontier.peaks();
        let mut current = peaks
            .iter()
            .find(|(peak_level, _)| *peak_level == level)
            .unwrap()
            .1;
        let local_index = u64::from(index) - start;
        let mut siblings = vec![[0; 32]; level as usize];
        for path_level in (0..level as usize).rev() {
            let (left, right) = nodes.get(&current).unwrap();
            if (local_index >> path_level) & 1 == 0 {
                siblings[path_level] = *right;
                current = *left;
            } else {
                siblings[path_level] = *left;
                current = *right;
            }
        }
        let other_peaks = peaks
            .into_iter()
            .filter(|(peak_level, _)| *peak_level != level)
            .collect();
        HeaderMerklePath::from_parts(index, frontier.count(), level, siblings, other_peaks).unwrap()
    }

    fn dense_root(headers: &[BlockHeader]) -> HeaderDigest {
        let mut peaks = Vec::new();
        let mut offset = 0usize;
        let count = headers.len() as u64;
        for level in peak_levels(count) {
            let width = 1usize << level;
            let mut nodes = headers[offset..offset + width]
                .iter()
                .map(|header| header_leaf(header.height, &header.hash()))
                .collect::<Vec<_>>();
            for node_level in 0..level {
                nodes = nodes
                    .chunks_exact(2)
                    .map(|pair| header_node(node_level, &pair[0], &pair[1]))
                    .collect();
            }
            peaks.push((level, nodes[0]));
            offset += width;
        }
        assert_eq!(offset, headers.len());
        peaks.sort_by_key(|(level, _)| core::cmp::Reverse(*level));
        finalize_root(count, &peaks)
    }

    #[test]
    fn frontier_mmr_matches_independent_append_reference_at_carry_boundaries() {
        let headers = make_headers(65);
        let mut frontier = HeaderFrontier::empty();
        assert_eq!(frontier.root(), dense_root(&[]));
        for (index, header) in headers.iter().enumerate() {
            frontier.append(header).unwrap();
            assert_eq!(frontier.root(), dense_root(&headers[..=index]));
        }
        let mut reordered = headers.clone();
        reordered.swap(0, 1);
        assert_ne!(frontier.root(), dense_root(&reordered));
    }

    #[test]
    fn mmr_paths_bind_headers_height_count_branch_and_peak_order() {
        let headers = make_headers(65);
        let nodes = nodes_for(&headers);
        let mut frontier = HeaderFrontier::empty();
        for header in &headers {
            frontier.append(header).unwrap();
        }
        let root = frontier.root();
        for header in &headers {
            let path = path_for(&frontier, &nodes, header.height);
            assert!(path.verify(header, &root));
            let mut altered = header.clone();
            altered.target ^= 1;
            assert!(!path.verify(&altered, &root));
            altered = header.clone();
            altered.height ^= 1;
            assert!(!path.verify(&altered, &root));
            assert!(!HeaderMerklePath::from_parts(
                path.index(),
                path.count() + 1,
                path.peak_level(),
                path.siblings().to_vec(),
                path.other_peaks().to_vec(),
            )
            .is_ok_and(|other_count_path| other_count_path.verify(header, &root)));
        }

        let mut fork = headers[..64].to_vec();
        let mut fork_header = headers[64].clone();
        fork_header.timestamp += 1;
        fork.push(fork_header);
        let mut fork_frontier = HeaderFrontier::empty();
        for header in &fork {
            fork_frontier.append(header).unwrap();
        }
        assert_ne!(root, fork_frontier.root());
        let path = path_for(&frontier, &nodes, 64);
        assert!(!path.verify(&fork[64], &root));

        let small_headers = make_headers(7);
        let small_nodes = nodes_for(&small_headers);
        let mut small_frontier = HeaderFrontier::empty();
        for header in &small_headers {
            small_frontier.append(header).unwrap();
        }
        let path = path_for(&small_frontier, &small_nodes, 0);
        let mut swapped_peaks = path.other_peaks().to_vec();
        swapped_peaks.reverse();
        assert!(HeaderMerklePath::from_parts(
            path.index(),
            path.count(),
            path.peak_level(),
            path.siblings().to_vec(),
            swapped_peaks,
        )
        .is_err());
    }

    #[test]
    fn frontier_rejects_out_of_order_or_wrong_parent_without_changing_state() {
        let headers = make_headers(3);
        let mut frontier = HeaderFrontier::empty();
        assert!(frontier.append(&headers[1]).is_err());
        assert_eq!(frontier, HeaderFrontier::empty());
        frontier.append(&headers[0]).unwrap();
        let before = frontier.clone();
        assert!(frontier.append(&headers[0]).is_err());
        assert_eq!(frontier, before);
        let mut child = headers[1].clone();
        child.prev_hash = BlockHash::from_bytes([7; 32]);
        assert!(frontier.append(&child).is_err());
        assert_eq!(frontier, before);
    }

    #[test]
    fn frontier_serialization_roundtrips_empty_and_peak_shapes() {
        let headers = make_headers(65);
        let mut frontier = HeaderFrontier::empty();
        assert_eq!(frontier.root(), empty_root());
        assert_eq!(frontier.count(), 0);
        assert_eq!(frontier.tip_hash(), None);
        for next in std::iter::once(None).chain(headers.iter().map(Some)) {
            if let Some(header) = next {
                frontier.append(header).unwrap();
            }
            let encoded = frontier.to_vec();
            let decoded = HeaderFrontier::from_slice(&encoded).unwrap();
            assert_eq!(decoded, frontier);
            assert_eq!(decoded.root(), frontier.root());
            assert_eq!(encoded.len(), 41 + frontier.peaks().len() * 32);
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(HeaderFrontier::from_slice(&trailing).is_err());
            assert!(HeaderFrontier::from_slice(&encoded[..encoded.len() - 1]).is_err());
        }
    }

    #[test]
    fn path_encoding_rejects_truncation_count_level_peak_order_and_trailing() {
        let headers = make_headers(65);
        let nodes = nodes_for(&headers);
        let mut frontier = HeaderFrontier::empty();
        for header in &headers {
            frontier.append(header).unwrap();
        }
        let path = path_for(&frontier, &nodes, 64);
        let encoded = path.to_vec();
        assert!(encoded.len() <= HEADER_MERKLE_PATH_MAX_LEN);
        assert_eq!(HeaderMerklePath::from_slice(&encoded).unwrap(), path);
        assert!(HeaderMerklePath::from_slice(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(HeaderMerklePath::from_slice(&trailing).is_err());
        let mut malformed = encoded.clone();
        malformed[0] = 2;
        assert!(HeaderMerklePath::from_slice(&malformed).is_err());
        malformed = encoded.clone();
        malformed[5..13].copy_from_slice(&(HEADER_TREE_CAPACITY + 1).to_le_bytes());
        assert!(HeaderMerklePath::from_slice(&malformed).is_err());
        malformed = encoded.clone();
        malformed[13] = 1;
        assert!(HeaderMerklePath::from_slice(&malformed).is_err());
    }

    #[test]
    fn frontier_decoding_rejects_noncanonical_empty_tip() {
        let mut encoded = HeaderFrontier::empty().to_vec();
        encoded[9] = 1;
        assert!(HeaderFrontier::from_slice(&encoded).is_err());
    }

    #[test]
    fn full_capacity_is_representable_but_cannot_append() {
        let internal = [11; 32];
        let mut bytes = Writer::default();
        bytes
            .put_u8(HEADER_TREE_ENCODING_VERSION)
            .put_u64_le(HEADER_TREE_CAPACITY)
            .put(&[7; 32])
            .put(&internal);
        let mut frontier = HeaderFrontier::from_slice(&bytes.into_bytes()).unwrap();
        assert_eq!(frontier.peaks(), [(32, internal)]);
        assert_eq!(
            frontier.root(),
            finalize_root(HEADER_TREE_CAPACITY, &[(32, internal)])
        );
        let header = make_headers(1).remove(0);
        assert_eq!(frontier.append(&header), Err(Error::HeightExhausted));
    }
}
