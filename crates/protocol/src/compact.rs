//! Compact blocks: the minimum a light client needs to find its coins and
//! maintain the commitment tree without downloading full transactions.
//!
//! Per action it carries the nullifier, the coin commitment, the ephemeral
//! key and the leading [`COMPACT_COIN_LEAD`] bytes of the coin ciphertext.
//! A light client trial-decrypts the lead against its incoming viewing key
//! and confirms a hit against the commitment; every commitment lets it
//! append to its witness tree, and every nullifier lets it detect spends.
//! The block hash and height let it track its scan position and reorgs.

use crypto::encryption::{KemCiphertext, KEM_CIPHERTEXT_LEN};

use crate::block::{Block, BlockHash};
use crate::bytes::{Encodable, Reader, Writer};
use crate::coin::ExtractedCoinCommitment;
use crate::encryption::COMPACT_COIN_LEAD;
use crate::nullifier::Nullifier;
use crate::tree_order::tree_transactions;
use crate::{Error, Result};

/// One action, stripped to what a light client reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactAction {
    /// The nullifier the action reveals.
    pub nullifier: Nullifier,
    /// The new coin's commitment.
    pub cmx: ExtractedCoinCommitment,
    /// ML-KEM ciphertext used to derive this coin's encryption key.
    pub kem_ciphertext: KemCiphertext,
    /// The leading bytes of the coin ciphertext.
    pub enc_lead: [u8; COMPACT_COIN_LEAD],
}

impl Encodable for CompactAction {
    fn write(&self, w: &mut Writer) {
        w.put(&self.nullifier.to_bytes())
            .put(&self.cmx.to_bytes())
            .put(&self.kem_ciphertext.to_bytes())
            .put(&self.enc_lead);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let nullifier = Nullifier::from_bytes(&r.take_array()?)?;
        let cmx = ExtractedCoinCommitment::from_bytes(&r.take_array()?)?;
        let kem_ciphertext = KemCiphertext::from_bytes(r.take(KEM_CIPHERTEXT_LEN)?)?;
        let enc_lead = r.take_array()?;
        Ok(Self {
            nullifier,
            cmx,
            kem_ciphertext,
            enc_lead,
        })
    }
}

/// A block reduced to its compact actions, in tree order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    /// The block height.
    pub height: u32,
    /// The block hash, so a light client can track reorgs.
    pub hash: BlockHash,
    /// The actions whose commitments the block appends, in transaction order.
    pub actions: Vec<CompactAction>,
}

impl CompactBlock {
    /// Reduces a full block to its compact form.
    pub fn from_block(block: &Block) -> Result<Self> {
        let tree = tree_transactions(block)?;
        let mut actions = Vec::new();
        for tx in tree {
            for action in tx.actions() {
                let body = action.body();
                let mut enc_lead = [0u8; COMPACT_COIN_LEAD];
                enc_lead
                    .copy_from_slice(&body.encrypted_coin().enc_ciphertext()[..COMPACT_COIN_LEAD]);
                actions.push(CompactAction {
                    nullifier: *body.nullifier(),
                    cmx: *body.cmx(),
                    kem_ciphertext: body.encrypted_coin().kem_ciphertext().clone(),
                    enc_lead,
                });
            }
        }
        Ok(Self {
            height: block.header().height,
            hash: block.hash(),
            actions,
        })
    }
}

impl Encodable for CompactBlock {
    fn write(&self, w: &mut Writer) {
        w.put(&self.height.to_le_bytes()).put(self.hash.as_bytes());
        // A block holds at most MAX_BLOCK_TRANSACTIONS * 16 actions, which
        // fits a u32 with room to spare.
        w.put(
            &u32::try_from(self.actions.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for action in &self.actions {
            action.write(w);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let height = u32::from_le_bytes(r.take_array()?);
        let hash = BlockHash::from_bytes(r.take_array()?);
        let count = u32::from_le_bytes(r.take_array()?);
        let max = crate::consensus::MAX_BLOCK_TRANSACTIONS
            .saturating_mul(*crate::consensus::ACTION_CLASSES.last().unwrap_or(&16));
        if count as usize > max {
            return Err(Error::Malformed("too many compact actions"));
        }
        let actions = (0..count)
            .map(|_| CompactAction::read(r))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            height,
            hash,
            actions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compact_block_round_trips_through_bytes() {
        let action = CompactAction {
            nullifier: Nullifier::from_base(&crypto::pallas::Base::from(7u64)),
            cmx: ExtractedCoinCommitment::from_bytes(&[0; 32]).unwrap(),
            kem_ciphertext: KemCiphertext::from_bytes(&[0u8; KEM_CIPHERTEXT_LEN]).unwrap(),
            enc_lead: [9u8; COMPACT_COIN_LEAD],
        };
        let block = CompactBlock {
            height: 5,
            hash: BlockHash::from_bytes([3; 32]),
            actions: vec![action.clone(), action],
        };
        let mut w = Writer::with_capacity(256);
        block.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let decoded = CompactBlock::read(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn decoding_rejects_an_absurd_action_count() {
        let mut w = Writer::with_capacity(40);
        w.put(&1u32.to_le_bytes())
            .put(BlockHash::ZERO.as_bytes())
            .put(&u32::MAX.to_le_bytes());
        let bytes = w.into_bytes();
        assert!(CompactBlock::read(&mut Reader::new(&bytes)).is_err());
    }
}
