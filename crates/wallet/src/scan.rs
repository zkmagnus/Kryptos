//! Trial decryption of one block into owned coins.

use protocol::amount::RawCoin;
use protocol::block::Block;
use protocol::bytes::{Encodable, Reader, Writer};
use protocol::coin::{Coin, RandomSeed, Rho};
use protocol::compact::CompactBlock;
use protocol::nullifier::Nullifier;
use protocol::transaction::{Transaction, TxId};

use crate::keys::{ScanKeys, WalletKeys};
use crate::Result;

/// A coin the wallet owns.
#[derive(Clone, Debug)]
pub struct OwnedCoin {
    /// The coin.
    pub coin: Coin,
    /// Its position in the commitment tree.
    pub position: u64,
    /// The nullifier spending it reveals.
    pub nullifier: Nullifier,
    /// Height of the block that created it.
    pub height: u32,
    /// Height of the block that spent it, once seen.
    pub spent_at: Option<u32>,
    /// The transaction that created it; unknown after a compact scan.
    pub txid: Option<TxId>,
    /// The transaction that spent it, once seen in a full scan.
    pub spent_by: Option<TxId>,
    /// Whether the payment used the old shared ML-KEM address key.
    pub legacy_address: bool,
}

impl Encodable for OwnedCoin {
    fn write(&self, w: &mut Writer) {
        self.coin.write(w);
        w.put_u64_le(self.position);
        self.nullifier.write(w);
        w.put(&self.height.to_le_bytes());
        match self.spent_at {
            Some(h) => {
                w.put_u8(1).put(&h.to_le_bytes());
            }
            None => {
                w.put_u8(0);
            }
        }
        write_txid(w, self.txid);
        write_txid(w, self.spent_by);
        w.put_u8(u8::from(!self.legacy_address));
    }

    fn read(r: &mut Reader<'_>) -> protocol::Result<Self> {
        let coin = Coin::read(r)?;
        let position = r.take_u64_le()?;
        let nullifier = Nullifier::read(r)?;
        let height = u32::from_le_bytes(r.take_array()?);
        let spent_at = match r.take_u8()? {
            0 => None,
            1 => Some(u32::from_le_bytes(r.take_array()?)),
            _ => return Err(protocol::Error::Malformed("spent flag")),
        };
        let txid = read_txid(r)?;
        let spent_by = read_txid(r)?;
        // Original wallet rows end after spent_by and all used shared keys.
        // Rows are stored individually; this optional suffix is not a wire
        // transaction encoding or a concatenated list encoding.
        let legacy_address = match r.remaining() {
            0 => true,
            _ => match r.take_u8()? {
                0 => true,
                1 => false,
                _ => return Err(protocol::Error::Malformed("coin address scheme")),
            },
        };
        Ok(Self {
            coin,
            position,
            nullifier,
            height,
            spent_at,
            txid,
            spent_by,
            legacy_address,
        })
    }
}

/// An optional transaction id: a presence byte, then the id.
fn write_txid(w: &mut Writer, txid: Option<TxId>) {
    match txid {
        Some(id) => {
            w.put_u8(1).put(id.as_bytes());
        }
        None => {
            w.put_u8(0);
        }
    }
}

fn read_txid(r: &mut Reader<'_>) -> protocol::Result<Option<TxId>> {
    match r.take_u8()? {
        0 => Ok(None),
        1 => Ok(Some(TxId::from_bytes(r.take_array()?))),
        _ => Err(protocol::Error::Malformed("txid flag")),
    }
}

/// What scanning one block found.
#[derive(Debug, Default)]
pub struct BlockScan {
    /// Every commitment in the block, in transaction order.
    pub leaves: Vec<crypto::pallas::Base>,
    /// Coins the wallet owns, with positions relative to `first_position`.
    pub found: Vec<OwnedCoin>,
    /// Every nullifier the block spent, with the spending transaction
    /// when the scan knew it.
    pub spent: Vec<(Nullifier, Option<TxId>)>,
}

/// A valid coin used for the nullifier computation on failed trial decryption.
/// Receiver decryption itself always derives a recipient and commitment;
/// both outcomes then compute a nullifier here. This balances cryptographic
/// work, but allocations and persistence can still depend on ownership.
struct StandIn {
    coin: Coin,
}

impl StandIn {
    fn new(keys: &WalletKeys) -> Result<Self> {
        let address = keys.default_address()?;
        Ok(Self {
            coin: Coin::new(
                *address.diversifier(),
                *address.pk_d(),
                RawCoin::ZERO,
                Rho::from_nullifier(&Nullifier::from_bytes(&[0; 32])?)?,
                RandomSeed::from_bytes([0; 32]),
            ),
        })
    }

    /// Computes one nullifier, regardless of whether trial decryption matched.
    fn nullifier(&self, keys: &WalletKeys, coin: Option<&Coin>) -> Result<Nullifier> {
        // The non-match result is discarded by the caller. Keep the work from
        // being optimized away, including in builds with link-time optimization.
        Ok(std::hint::black_box(
            coin.unwrap_or(&self.coin).nullifier(keys.nullifier_key())?,
        ))
    }
}

/// Decrypts the outputs `block` appends to the tree with `keys`: `tree`
/// lists those transactions in block order. Positions start at
/// `first_position`, the tree size before the
/// block. Spends are every nullifier the block itself reveals. Trial decryption
/// and nullifier derivation do comparable cryptographic work for owned and
/// foreign notes. Network fetch timing must still be isolated from scanning.
///
/// # Errors
/// Fails if a decrypted coin cannot derive its nullifier.
/// This convenience wrapper scans the default address. Use [`scan_block_with_keys`] for other new address indices.
pub fn scan_block(
    keys: &WalletKeys,
    block: &Block,
    tree: &[&Transaction],
    first_position: u64,
) -> Result<BlockScan> {
    let scan_keys = ScanKeys::new(keys, 0, 1)?;
    scan_block_with_keys(keys, &scan_keys, block, tree, first_position)
}

/// Scans a full block using a previously derived, explicit address range.
/// Every candidate key active at this height is tried, including after a match.
///
/// # Errors
/// Rejects a context for another wallet and propagates coin/nullifier errors.
pub fn scan_block_with_keys(
    keys: &WalletKeys,
    scan_keys: &ScanKeys,
    block: &Block,
    tree: &[&Transaction],
    first_position: u64,
) -> Result<BlockScan> {
    scan_keys.check_wallet(keys)?;
    let mut scan = BlockScan::default();
    for tx in block.transactions() {
        let txid = tx.txid();
        scan.spent.extend(
            tx.actions()
                .iter()
                .map(|a| (*a.body().nullifier(), Some(txid))),
        );
    }
    let stand_in = StandIn::new(keys)?;
    for tx in tree {
        let txid = tx.txid();
        for action in tx.actions() {
            let body = action.body();
            let position =
                first_position.saturating_add(u64::try_from(scan.leaves.len()).unwrap_or(u64::MAX));
            scan.leaves.push(*body.cmx().inner());
            let rho = Rho::from_nullifier(body.nullifier())?;
            let decrypted = scan_keys.trial_decrypt(block.header().height, |ivk, receiver_key| {
                ivk.decrypt_coin(receiver_key, body.encrypted_coin(), rho, body.cmx())
            });
            let nullifier = stand_in.nullifier(keys, decrypted.as_ref().map(|(coin, _)| coin))?;
            let Some((coin, legacy_address)) = decrypted else {
                continue;
            };
            if coin.value().raw() == 0 {
                continue;
            }
            scan.found.push(OwnedCoin {
                coin,
                position,
                nullifier,
                height: block.header().height,
                spent_at: None,
                txid: Some(txid),
                spent_by: None,
                legacy_address,
            });
        }
    }
    Ok(scan)
}

/// Detects owned coins in one compact block. Produces the same leaves as
/// [`scan_block`] and the same owned coins, without transaction identifiers,
/// since a compact block omits them. Its spent nullifiers are those
/// of its block-order actions. It includes the coinbase, which differs only
/// in dummy spends that never match a wallet coin.
///
/// # Errors
/// Fails if a detected coin cannot derive its nullifier.
/// This convenience wrapper scans the default address. Use [`scan_compact_block_with_keys`] for other new indices.
pub fn scan_compact_block(
    keys: &WalletKeys,
    block: &CompactBlock,
    first_position: u64,
) -> Result<BlockScan> {
    let scan_keys = ScanKeys::new(keys, 0, 1)?;
    scan_compact_block_with_keys(keys, &scan_keys, block, first_position)
}

/// Scans a compact block using a previously derived address range. Every
/// candidate must reconstruct and check the commitment before accepting a coin.
///
/// # Errors
/// Rejects a context for another wallet and propagates coin/nullifier errors.
pub fn scan_compact_block_with_keys(
    keys: &WalletKeys,
    scan_keys: &ScanKeys,
    block: &CompactBlock,
    first_position: u64,
) -> Result<BlockScan> {
    scan_keys.check_wallet(keys)?;
    let mut scan = BlockScan::default();
    let stand_in = StandIn::new(keys)?;
    for action in &block.actions {
        let position =
            first_position.saturating_add(u64::try_from(scan.leaves.len()).unwrap_or(u64::MAX));
        scan.leaves.push(*action.cmx.inner());
        scan.spent.push((action.nullifier, None));
        let rho = Rho::from_nullifier(&action.nullifier)?;
        let detected = scan_keys.trial_decrypt(block.height, |ivk, receiver_key| {
            ivk.detect_coin(
                receiver_key,
                &action.kem_ciphertext,
                &action.enc_lead,
                rho,
                &action.cmx,
            )
        });
        let nullifier = stand_in.nullifier(keys, detected.as_ref().map(|(coin, _)| coin))?;
        let Some((coin, legacy_address)) = detected else {
            continue;
        };
        if coin.value().raw() == 0 {
            continue;
        }
        scan.found.push(OwnedCoin {
            coin,
            position,
            nullifier,
            height: block.height,
            spent_at: None,
            txid: None,
            spent_by: None,
            legacy_address,
        });
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use crypto::keys::SpendingKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn full_and_compact_scans_agree_for_owned_foreign_zero_and_mismatched_notes() {
        use crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
        use crypto::keys::SpendAuthorizingKey;
        use crypto::signature::{
            BindingSignature, RandomizedSigningKey, SpendAuthRandomizer, SpendAuthSignature,
        };
        use protocol::action::ActionBody;
        use protocol::block::{empty_header, BlockHash};
        use protocol::compact::CompactAction;
        use protocol::encryption::{encrypt_coin, COMPACT_COIN_LEAD};
        use protocol::transaction::Anchor;
        use transaction_proof::{ActionProofEnvelope, Proof};

        let mut rng = ChaCha20Rng::seed_from_u64(70);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let foreign = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let mut actions = Vec::new();
        let mut compact = CompactBlock {
            height: 7,
            hash: BlockHash::ZERO,
            actions: Vec::new(),
        };
        let mut expected_coin = None;
        for (index, (recipient, value)) in [(&keys, 42), (&foreign, 43), (&keys, 0), (&keys, 44)]
            .into_iter()
            .enumerate()
        {
            let address = recipient.default_address().unwrap();
            let nf = Nullifier::from_base(&crypto::pallas::Base::from(index as u64 + 1));
            let coin = Coin::new(
                *address.diversifier(),
                *address.pk_d(),
                RawCoin::from_raw(value).unwrap(),
                Rho::from_nullifier(&nf).unwrap(),
                RandomSeed::random(&mut rng),
            );
            let cmx = coin.cmx().unwrap();
            let cv = ValueCommitment::commit(0, &ValueCommitTrapdoor::random(&mut rng));
            let encrypted = encrypt_coin(&coin, address.kem_key(), &mut rng).unwrap();
            let rk = RandomizedSigningKey::new(
                &SpendAuthorizingKey::derive(keys.spending_key()).unwrap(),
                &SpendAuthRandomizer::random(&mut rng),
            )
            .unwrap()
            .verification_key();
            // Authentication and decoding succeed for the final note, but its
            // action rho is inconsistent with its commitment.
            let action_nf = if index == 3 {
                Nullifier::from_bytes(&[0; 32]).unwrap()
            } else {
                nf
            };
            let mut lead = [0; COMPACT_COIN_LEAD];
            lead.copy_from_slice(&encrypted.enc_ciphertext()[..COMPACT_COIN_LEAD]);
            compact.actions.push(CompactAction {
                nullifier: action_nf,
                cmx,
                kem_ciphertext: encrypted.kem_ciphertext().clone(),
                enc_lead: lead,
            });
            actions.push(
                ActionBody::new(action_nf, rk, cmx, cv, encrypted)
                    .sign(SpendAuthSignature::from_bytes([0; 64])),
            );
            if index == 0 {
                expected_coin = Some(coin);
            }
        }
        let tx = Transaction::new(
            Anchor::from_base(crypto::pallas::Base::zero()),
            RawCoin::ZERO,
            actions,
            ActionProofEnvelope::new(&Proof::from_bytes(vec![
                0;
                protocol::consensus::proof_len(4)
                    .unwrap()
            ]))
            .unwrap(),
            BindingSignature::from_bytes([0; 64]),
        )
        .unwrap();
        let block = Block::new(empty_header(7, BlockHash::ZERO, *tx.anchor()), vec![tx]);
        let tree = vec![&block.transactions()[0]];
        let full = scan_block(&keys, &block, &tree, 20).unwrap();
        let light = scan_compact_block(&keys, &compact, 20).unwrap();
        assert_eq!(full.leaves, light.leaves);
        assert_eq!(
            full.spent.iter().map(|(nf, _)| *nf).collect::<Vec<_>>(),
            light.spent.iter().map(|(nf, _)| *nf).collect::<Vec<_>>()
        );
        for scan in [&full, &light] {
            assert_eq!(scan.found.len(), 1);
            let found = &scan.found[0];
            assert_eq!(found.position, 20);
            assert_eq!(found.coin.value().raw(), 42);
            assert!(!found.legacy_address);
            assert_eq!(
                found.nullifier,
                expected_coin
                    .as_ref()
                    .unwrap()
                    .nullifier(keys.nullifier_key())
                    .unwrap()
            );
        }
        assert_eq!(full.found[0].txid, Some(tree[0].txid()));
        assert_eq!(light.found[0].txid, None);
    }

    #[test]
    fn owned_coin_rows_preserve_the_address_scheme_and_read_legacy_rows() {
        let keys = WalletKeys::from_spending_key(SpendingKey::from_bytes([91; 32])).unwrap();
        let coin = StandIn::new(&keys).unwrap().coin;
        let mut row = OwnedCoin {
            nullifier: coin.nullifier(keys.nullifier_key()).unwrap(),
            coin,
            position: 10,
            height: 3,
            spent_at: Some(4),
            txid: Some(TxId::from_bytes([1; 32])),
            spent_by: Some(TxId::from_bytes([2; 32])),
            legacy_address: false,
        };
        let encoded = row.to_vec();
        let decoded = OwnedCoin::from_slice(&encoded).unwrap();
        assert!(!decoded.legacy_address);
        assert_eq!(decoded.to_vec(), encoded);

        let legacy_bytes = &encoded[..encoded.len() - 1];
        let legacy = OwnedCoin::from_slice(legacy_bytes).unwrap();
        assert!(legacy.legacy_address);
        row.legacy_address = true;
        assert_eq!(legacy.to_vec(), row.to_vec());
        assert!(OwnedCoin::from_slice(&row.to_vec()).unwrap().legacy_address);

        let mut unknown = legacy_bytes.to_vec();
        unknown.push(2);
        assert!(OwnedCoin::from_slice(&unknown).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(OwnedCoin::from_slice(&trailing).is_err());
    }

    #[test]
    fn the_stand_in_has_a_valid_nullifier() {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1)))
                .unwrap();
        let stand_in = StandIn::new(&keys).unwrap();
        assert_eq!(
            stand_in.nullifier(&keys, None).unwrap(),
            stand_in.coin.nullifier(keys.nullifier_key()).unwrap(),
        );
        assert_eq!(stand_in.coin.value().raw(), 0);
    }
}
