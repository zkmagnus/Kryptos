//! Transaction order used when appending block commitments to the tree.

use crate::block::Block;
use crate::Result;

/// The transactions whose outputs `block` appends to the tree, in block
pub fn tree_transactions(block: &Block) -> Result<Vec<&crate::transaction::Transaction>> {
    Ok(block.transactions().iter().collect())
}
