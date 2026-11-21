//! Persistent sparse Merkle commitment to the set of spent nullifiers.
//!
//! The key is the canonical little-endian encoding of a Pallas base-field
//! element. The tree is 255 levels deep and stores only non-empty internal
//! nodes. Internal nodes are content-addressed by a tree- and level-tagged
//! Poseidon hash, so roots can be shared by blocks on different branches.

use std::collections::{HashMap, HashSet};

use crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use crypto::pallas;
use crypto::poseidon::hash;
use ff::Field;
use protocol::nullifier::Nullifier;
use protocol::transaction::Anchor;

use crate::{Error, Result};

/// Number of bits in a canonical Pallas base-field representation.
pub const NULLIFIER_TREE_DEPTH: usize = 255;

const NF_TREE_TAG: u64 = 0x5248_4e46; // "RHNF"
const NF_LEAF_TAG: u64 = 0x4e46_4c46; // "NFLF"
const NF_NODE_TAG: u64 = 0x4e46_4e44; // "NFND"
const NF_TREE_VERSION: u64 = 1;
const NF_DOMAIN_TAG: u64 = 0x0052_484e_4644_4f4d; // "RHNF-DOM"

/// A stored non-empty internal node. `level` is the height above the leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeRecord {
    pub level: u8,
    pub left: pallas::Base,
    pub right: pallas::Base,
}

impl NodeRecord {
    pub(crate) fn encode(self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = self.level;
        out[1..33].copy_from_slice(&base_to_bytes(&self.left));
        out[33..65].copy_from_slice(&base_to_bytes(&self.right));
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::Corrupt("nullifier tree node length"));
        }
        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];
        left_bytes.copy_from_slice(&bytes[1..33]);
        right_bytes.copy_from_slice(&bytes[33..65]);
        Ok(Self {
            level: bytes[0],
            left: base_from_bytes(&left_bytes)?,
            right: base_from_bytes(&right_bytes)?,
        })
    }
}

/// The result of inserting an ordered batch against a parent root.
///
/// The node overlay is private to storage and is written in the same redb
/// transaction as the block/root index when this transition is committed.
#[derive(Clone, Debug)]
pub struct NullifierTransition {
    parent: protocol::block::BlockHash,
    nullifiers: Vec<Nullifier>,
    root: Anchor,
    count: u64,
    nodes: Vec<(Encoded, NodeRecord)>,
}

impl NullifierTransition {
    pub(crate) fn new(
        parent: protocol::block::BlockHash,
        nullifiers: Vec<Nullifier>,
        root: Anchor,
        count: u64,
        nodes: Vec<(Encoded, NodeRecord)>,
    ) -> Self {
        Self {
            parent,
            nullifiers,
            root,
            count,
            nodes,
        }
    }

    /// The resulting spent-nullifier set root.
    pub fn root(&self) -> Anchor {
        self.root
    }

    /// Number of distinct nullifiers in the resulting set.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The block whose committed nullifier root is being extended.
    pub fn parent(&self) -> protocol::block::BlockHash {
        self.parent
    }

    /// Nullifiers, in the canonical block transaction/action order.
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    pub(crate) fn nodes(&self) -> &[(Encoded, NodeRecord)] {
        &self.nodes
    }
}

/// A non-membership path for a nullifier relative to a root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierPath {
    siblings: Vec<pallas::Base>,
}

#[derive(Clone, Copy)]
struct Entry {
    key: Encoded,
    value: pallas::Base,
    order: Encoded,
}

impl NullifierPath {
    /// Siblings ordered leaf-to-root. There are exactly 255 entries.
    pub fn siblings(&self) -> &[pallas::Base] {
        &self.siblings
    }

    /// Verify this absence witness against `root`.
    pub fn verifies(&self, chain_id: &[u8; 32], root: Anchor, nullifier: &Nullifier) -> bool {
        if self.siblings.len() != NULLIFIER_TREE_DEPTH {
            return false;
        }
        let key = nullifier.to_bytes();
        let domain = domain_field(chain_id);
        let mut node = pallas::Base::ZERO;
        for (index, sibling) in self.siblings.iter().enumerate() {
            let Some(level) = index
                .checked_add(1)
                .and_then(|level| u8::try_from(level).ok())
            else {
                return false;
            };
            node = if key_bit(&key, index) {
                node_hash_for(domain, level, *sibling, node)
            } else {
                node_hash_for(domain, level, node, *sibling)
            };
        }
        Anchor::from_base(node) == root
    }
}

/// The canonical empty root for the nullifier set.
pub fn empty_root(chain_id: &[u8; 32]) -> Anchor {
    Anchor::from_base(empty_roots(domain_field(chain_id))[NULLIFIER_TREE_DEPTH])
}

/// Recompute the set root from a snapshot, rejecting duplicate nullifiers.
pub fn root_from_set(chain_id: &[u8; 32], nullifiers: &[Nullifier]) -> Result<Anchor> {
    let domain = domain_field(chain_id);
    let empty = empty_roots(domain);
    let entries =
        sorted_entries(nullifiers)?.ok_or(Error::Corrupt("duplicate nullifier in snapshot"))?;
    let root = compute_set_root(domain, &empty, &entries, NULLIFIER_TREE_DEPTH)?;
    Ok(Anchor::from_base(root))
}

/// Builds a sparse-tree node overlay for an already known set. The returned
/// nodes are content-addressed and can be committed with their block roots.
pub(crate) fn build_set(
    chain_id: &[u8; 32],
    nullifiers: &[Nullifier],
) -> Result<(Anchor, u64, Vec<(Encoded, NodeRecord)>)> {
    let Some((root, count, nodes)) = transition(
        chain_id,
        *empty_root(chain_id).inner(),
        0,
        nullifiers,
        |_| Ok(None),
    )?
    else {
        return Err(Error::Corrupt("duplicate nullifier in snapshot"));
    };
    Ok((root, count, nodes))
}

/// Mark every non-empty internal node reachable from `roots`.
pub(crate) fn reachable_nodes(
    chain_id: &[u8; 32],
    roots: &[Anchor],
    mut load_node: impl FnMut(&Encoded) -> Result<Option<NodeRecord>>,
) -> Result<HashSet<Encoded>> {
    let domain = domain_field(chain_id);
    let empty = empty_roots(domain);
    let mut marked = HashSet::new();
    let mut stack = roots
        .iter()
        .map(|root| (*root.inner(), NULLIFIER_TREE_DEPTH))
        .collect::<Vec<_>>();
    while let Some((node_hash, level)) = stack.pop() {
        if level == 0 || node_hash == empty[level] {
            continue;
        }
        let key = base_to_bytes(&node_hash);
        if !marked.insert(key) {
            continue;
        }
        let record = load_node(&key)?.ok_or(Error::Corrupt("missing reachable nullifier node"))?;
        if usize::from(record.level) != level
            || node_hash_for(domain, record.level, record.left, record.right) != node_hash
        {
            return Err(Error::Corrupt("invalid reachable nullifier node"));
        }
        let child_level = level
            .checked_sub(1)
            .ok_or(Error::Corrupt("nullifier tree level"))?;
        stack.push((record.left, child_level));
        stack.push((record.right, child_level));
    }
    Ok(marked)
}

/// Insert a batch into `parent_root`, returning `None` if any nullifier is
/// already present. New nodes are returned as a content-addressed overlay.
pub(crate) fn transition(
    chain_id: &[u8; 32],
    parent_root: pallas::Base,
    parent_count: u64,
    nullifiers: &[Nullifier],
    mut load_node: impl FnMut(&Encoded) -> Result<Option<NodeRecord>>,
) -> Result<Option<(Anchor, u64, Vec<(Encoded, NodeRecord)>)>> {
    let mut overlay = HashMap::new();
    let domain = domain_field(chain_id);
    let empty = empty_roots(domain);
    let Some(entries) = sorted_entries(nullifiers)? else {
        return Ok(None);
    };
    let empty_overlay = HashMap::new();
    let Some(root) = update_subtree(
        domain,
        &empty,
        parent_root,
        NULLIFIER_TREE_DEPTH,
        &entries,
        &empty_overlay,
        &mut load_node,
        &mut overlay,
    )?
    else {
        return Ok(None);
    };
    let mut nodes = overlay.into_iter().collect::<Vec<_>>();
    nodes.sort_by(|(a, _), (b, _)| a.cmp(b));
    let count = parent_count
        .checked_add(
            u64::try_from(nullifiers.len()).map_err(|_| Error::Corrupt("nullifier count"))?,
        )
        .ok_or(Error::Corrupt("nullifier count overflow"))?;
    Ok(Some((Anchor::from_base(root), count, nodes)))
}

/// Produce a path witnessing that `nullifier` is absent from `root`.
pub(crate) fn non_membership_path(
    chain_id: &[u8; 32],
    root: pallas::Base,
    nullifier: &Nullifier,
    mut load_node: impl FnMut(&Encoded) -> Result<Option<NodeRecord>>,
) -> Result<Option<NullifierPath>> {
    let overlay = HashMap::new();
    let domain = domain_field(chain_id);
    let empty = empty_roots(domain);
    let key = nullifier.to_bytes();
    let mut node_hash = root;
    let mut siblings = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
    for level in (1..=NULLIFIER_TREE_DEPTH).rev() {
        let (left, right) = children(domain, &empty, node_hash, level, &overlay, &mut load_node)?;
        let child_level = level
            .checked_sub(1)
            .ok_or(Error::Corrupt("nullifier tree level"))?;
        let bit = key_bit(&key, child_level);
        if bit {
            siblings.push(left);
            node_hash = right;
        } else {
            siblings.push(right);
            node_hash = left;
        }
    }
    if node_hash != empty[0] {
        return Ok(None);
    }
    siblings.reverse();
    Ok(Some(NullifierPath { siblings }))
}

fn sorted_entries(nullifiers: &[Nullifier]) -> Result<Option<Vec<Entry>>> {
    let mut entries = nullifiers
        .iter()
        .map(|nullifier| {
            let key = nullifier.to_bytes();
            Ok(Entry {
                key,
                value: nullifier.to_base()?,
                order: path_order(&key),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|a, b| a.order.cmp(&b.order));
    if entries.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Ok(None);
    }
    Ok(Some(entries))
}

fn path_order(key: &Encoded) -> Encoded {
    let mut order = [0u8; 32];
    for (index, output_bit) in (0..NULLIFIER_TREE_DEPTH).zip((0..NULLIFIER_TREE_DEPTH).rev()) {
        if key_bit(key, index) {
            order[output_bit / 8] |= 0x80 >> (output_bit % 8);
        }
    }
    order
}

fn compute_set_root(
    domain: pallas::Base,
    empty: &[pallas::Base; NULLIFIER_TREE_DEPTH + 1],
    entries: &[Entry],
    level: usize,
) -> Result<pallas::Base> {
    if entries.is_empty() {
        return Ok(empty[level]);
    }
    if level == 0 {
        return entries
            .first()
            .map(|entry| leaf_hash(domain, entry.value))
            .ok_or(Error::Corrupt("nullifier snapshot leaf missing"));
    }
    let child_level = level
        .checked_sub(1)
        .ok_or(Error::Corrupt("nullifier tree level"))?;
    let split = entries.partition_point(|entry| !key_bit(&entry.key, child_level));
    let left = compute_set_root(domain, empty, &entries[..split], child_level)?;
    let right = compute_set_root(domain, empty, &entries[split..], child_level)?;
    Ok(node_hash_for(
        domain,
        u8::try_from(level).map_err(|_| Error::Corrupt("nullifier tree level"))?,
        left,
        right,
    ))
}

#[allow(clippy::too_many_arguments)]
fn update_subtree(
    domain: pallas::Base,
    empty: &[pallas::Base; NULLIFIER_TREE_DEPTH + 1],
    root: pallas::Base,
    level: usize,
    entries: &[Entry],
    empty_overlay: &HashMap<Encoded, NodeRecord>,
    load_node: &mut impl FnMut(&Encoded) -> Result<Option<NodeRecord>>,
    overlay: &mut HashMap<Encoded, NodeRecord>,
) -> Result<Option<pallas::Base>> {
    if entries.is_empty() {
        return Ok(Some(root));
    }
    if level == 0 {
        if root != empty[0] || entries.len() != 1 {
            return Ok(None);
        }
        return Ok(Some(leaf_hash(domain, entries[0].value)));
    }
    let (left, right) = children(domain, empty, root, level, empty_overlay, load_node)?;
    let child_level = level
        .checked_sub(1)
        .ok_or(Error::Corrupt("nullifier tree level"))?;
    let split = entries.partition_point(|entry| !key_bit(&entry.key, child_level));
    let Some(new_left) = update_subtree(
        domain,
        empty,
        left,
        child_level,
        &entries[..split],
        empty_overlay,
        load_node,
        overlay,
    )?
    else {
        return Ok(None);
    };
    let Some(new_right) = update_subtree(
        domain,
        empty,
        right,
        child_level,
        &entries[split..],
        empty_overlay,
        load_node,
        overlay,
    )?
    else {
        return Ok(None);
    };
    let level_byte = u8::try_from(level).map_err(|_| Error::Corrupt("nullifier tree level"))?;
    let new_root = node_hash_for(domain, level_byte, new_left, new_right);
    let record = NodeRecord {
        level: level_byte,
        left: new_left,
        right: new_right,
    };
    let encoded = base_to_bytes(&new_root);
    if overlay
        .insert(encoded, record)
        .is_some_and(|old| old != record)
    {
        return Err(Error::Corrupt("nullifier tree hash collision"));
    }
    Ok(Some(new_root))
}

fn children(
    domain: pallas::Base,
    empty: &[pallas::Base; NULLIFIER_TREE_DEPTH + 1],
    node_hash: pallas::Base,
    level: usize,
    overlay: &HashMap<Encoded, NodeRecord>,
    load_node: &mut impl FnMut(&Encoded) -> Result<Option<NodeRecord>>,
) -> Result<(pallas::Base, pallas::Base)> {
    if node_hash == empty[level] {
        let child_level = level
            .checked_sub(1)
            .ok_or(Error::Corrupt("nullifier tree level"))?;
        let empty_child = empty[child_level];
        return Ok((empty_child, empty_child));
    }
    let key = base_to_bytes(&node_hash);
    let record = match overlay.get(&key).copied() {
        Some(record) => Some(record),
        None => load_node(&key)?,
    }
    .ok_or(Error::Corrupt("missing nullifier tree node"))?;
    if usize::from(record.level) != level
        || node_hash_for(domain, record.level, record.left, record.right) != node_hash
    {
        return Err(Error::Corrupt("invalid nullifier tree node"));
    }
    Ok((record.left, record.right))
}

fn key_bit(key: &Encoded, index: usize) -> bool {
    let byte = index / 8;
    let bit = index % 8;
    (key[byte] >> bit) & 1 == 1
}

fn leaf_hash(domain: pallas::Base, key: pallas::Base) -> pallas::Base {
    hash([
        domain,
        pallas::Base::from(NF_TREE_TAG),
        pallas::Base::from(NF_LEAF_TAG),
        key,
    ])
}

fn node_hash_for(
    domain: pallas::Base,
    level: u8,
    left: pallas::Base,
    right: pallas::Base,
) -> pallas::Base {
    hash([
        domain,
        pallas::Base::from(NF_TREE_TAG),
        pallas::Base::from(NF_NODE_TAG),
        pallas::Base::from(u64::from(level)),
        left,
        right,
    ])
}

fn domain_field(chain_id: &[u8; 32]) -> pallas::Base {
    let mut limbs = [pallas::Base::ZERO; 4];
    for (index, chunk) in chain_id.chunks_exact(8).enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        limbs[index] = pallas::Base::from(u64::from_le_bytes(bytes));
    }
    hash([
        pallas::Base::from(NF_DOMAIN_TAG),
        pallas::Base::from(NF_TREE_VERSION),
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
    ])
}

fn empty_roots(domain: pallas::Base) -> [pallas::Base; NULLIFIER_TREE_DEPTH + 1] {
    let mut roots = [pallas::Base::ZERO; NULLIFIER_TREE_DEPTH + 1];
    for (child_level, level) in (0..NULLIFIER_TREE_DEPTH).zip(1..=NULLIFIER_TREE_DEPTH) {
        roots[level] = node_hash_for(
            domain,
            u8::try_from(level).unwrap_or(u8::MAX),
            roots[child_level],
            roots[child_level],
        );
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_and_membership_paths_are_canonical() {
        let nf = Nullifier::from_base(&pallas::Base::from(7));
        let chain_id = [1u8; 32];
        let empty = empty_root(&chain_id);
        let path = non_membership_path(&chain_id, *empty.inner(), &nf, |_| Ok(None))
            .unwrap()
            .unwrap();
        assert_eq!(path.siblings().len(), NULLIFIER_TREE_DEPTH);
        assert!(path.verifies(&chain_id, empty, &nf));

        let inserted = root_from_set(&chain_id, &[nf]).unwrap();
        assert_ne!(inserted, empty);
        assert!(matches!(
            root_from_set(&chain_id, &[nf, nf]),
            Err(Error::Corrupt("duplicate nullifier in snapshot"))
        ));
    }

    #[test]
    fn sparse_tree_roots_are_order_independent_and_detect_duplicates() {
        let a = Nullifier::from_base(&pallas::Base::from(1));
        let b = Nullifier::from_base(&pallas::Base::from(2));
        let chain_id = [9u8; 32];
        assert_eq!(
            root_from_set(&chain_id, &[a, b]).unwrap(),
            root_from_set(&chain_id, &[b, a]).unwrap()
        );
        assert_eq!(
            transition(
                &chain_id,
                *empty_root(&chain_id).inner(),
                0,
                &[a, b],
                |_| Ok(None),
            )
            .unwrap()
            .unwrap()
            .0,
            root_from_set(&chain_id, &[a, b]).unwrap()
        );
        assert!(transition(
            &chain_id,
            *empty_root(&chain_id).inner(),
            0,
            &[a, a],
            |_| Ok(None)
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn persisted_nodes_authenticate_nonmembership_and_bind_network() {
        let chain_id = [3u8; 32];
        let other_chain = [4u8; 32];
        let a = Nullifier::from_base(&pallas::Base::from(17));
        let b = Nullifier::from_base(&pallas::Base::from(29));
        let absent = Nullifier::from_base(&pallas::Base::from(31));
        let (root, count, records) = transition(
            &chain_id,
            *empty_root(&chain_id).inner(),
            0,
            &[a, b],
            |_| Ok(None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(count, 2);
        let nodes: HashMap<_, _> = records.into_iter().collect();
        let path = non_membership_path(&chain_id, *root.inner(), &absent, |key| {
            Ok(nodes.get(key).copied())
        })
        .unwrap()
        .unwrap();
        assert!(path.verifies(&chain_id, root, &absent));
        assert!(!path.verifies(&other_chain, root, &absent));
        assert!(non_membership_path(&chain_id, *root.inner(), &a, |key| {
            Ok(nodes.get(key).copied())
        })
        .unwrap()
        .is_none());

        assert!(transition(&chain_id, *root.inner(), count, &[a], |key| {
            Ok(nodes.get(key).copied())
        })
        .unwrap()
        .is_none());
        assert_ne!(empty_root(&chain_id), empty_root(&other_chain));
    }
}
