//! Inclusion receipts for transactions committed by v1 block headers.

use protocol::block::{Block, BlockHash, BlockHeader, TxMerklePath};
use protocol::header_tree::HeaderMerklePath;
use protocol::transaction::Transaction;

/// Header evidence tying a transaction's block to a named PoW-chain tip.
///
/// `tip_header.history_root` commits all headers below its height. This is a
/// membership witness, not proof of work: the receiver must authenticate the
/// tip and its chainwork under normal network rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderWitness {
    /// Header containing the transaction Merkle root.
    pub block_header: BlockHeader,
    /// The reference tip whose parent-history root authenticates the block.
    pub tip_header: BlockHeader,
    /// MMR inclusion path when the transaction block is below the tip.
    /// The path is absent exactly when the transaction block is the tip.
    pub history_path: Option<HeaderMerklePath>,
    /// Validated cumulative work at that tip, big-endian U256.
    pub tip_work: [u8; 32],
}

/// A portable transaction-inclusion receipt for a v1 transaction Merkle root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentReceipt {
    /// The transaction being proven.
    pub tx: Transaction,
    /// Transaction position within the committed block.
    pub tx_index: u32,
    /// Merkle authentication path, including the committed transaction count.
    pub tx_path: TxMerklePath,
    /// Hash of the block header that commits to the transaction root.
    pub block_commitment: BlockHash,
    /// Header ancestry and reference-tip work context.
    pub header_witness: HeaderWitness,
}

/// Why a transaction receipt failed structural verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// The transaction index, path, block hash, or transaction root disagrees.
    #[error("transaction inclusion path is invalid")]
    Inclusion,
    /// Headers do not form a contiguous ancestry ending at the named tip.
    #[error("header ancestry does not end at the named tip")]
    Ancestry,
}

impl PaymentReceipt {
    /// Creates a receipt from a block and an already selected header-history path.
    ///
    /// For older blocks, `history_path` must prove membership in the exact
    /// `tip_header.history_root`. It is omitted when the block is the tip
    /// itself because a header's history root covers only its ancestors.
    pub fn from_block(
        block: &Block,
        tx_index: usize,
        tip_header: &BlockHeader,
        tip_work: [u8; 32],
        history_path: Option<HeaderMerklePath>,
    ) -> Option<Self> {
        let header = block.header();
        if header.version != protocol::consensus::BLOCK_VERSION {
            return None;
        }
        let txids = block
            .transactions()
            .iter()
            .map(Transaction::txid)
            .collect::<Vec<_>>();
        let path = protocol::block::tx_merkle_path(&txids, tx_index)?;
        let history_matches = if header.height == tip_header.height {
            header.hash() == tip_header.hash() && history_path.is_none()
        } else {
            header.height < tip_header.height
                && tip_header.version == protocol::consensus::BLOCK_VERSION
                && history_path.as_ref().is_some_and(|path| {
                    path.count() == u64::from(tip_header.height)
                        && path.verify(header, &tip_header.history_root)
                })
        };
        if !history_matches {
            return None;
        }
        Some(Self {
            tx: block.transactions().get(tx_index)?.clone(),
            tx_index: u32::try_from(tx_index).ok()?,
            tx_path: path,
            block_commitment: header.hash(),
            header_witness: HeaderWitness {
                block_header: header.clone(),
                tip_header: tip_header.clone(),
                history_path,
                tip_work,
            },
        })
    }

    /// Checks transaction inclusion and header-tree membership to the named tip.
    ///
    /// This does not validate RandomX, DAA, or the numeric `tip_work`; callers
    /// must obtain that context from a normally validated header chain.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        let header = &self.header_witness.block_header;
        if header.version != protocol::consensus::BLOCK_VERSION
            || header.hash() != self.block_commitment
            || self.tx_path.index() != u64::from(self.tx_index)
            || !self.tx_path.verify(&self.tx.txid(), &header.tx_root)
        {
            return Err(ReceiptError::Inclusion);
        }
        let tip = &self.header_witness.tip_header;
        let history_matches = if header.height == tip.height {
            header.hash() == tip.hash() && self.header_witness.history_path.is_none()
        } else {
            header.height < tip.height
                && tip.version == protocol::consensus::BLOCK_VERSION
                && self
                    .header_witness
                    .history_path
                    .as_ref()
                    .is_some_and(|path| {
                        path.count() == u64::from(tip.height)
                            && path.verify(header, &tip.history_root)
                    })
        };
        if !history_matches {
            return Err(ReceiptError::Ancestry);
        }
        Ok(())
    }
}
