//! Trial decryption of one block into owned coins.

use protocol::amount::RawCoin;
use protocol::block::Block;
use protocol::bytes::{Encodable, Reader, Writer};
use protocol::coin::{Coin, RandomSeed, Rho};
use protocol::compact::CompactBlock;
use protocol::encryption::{decrypt_coin_with_ivk, detect_coin_with_ivk};
use protocol::memo::Memo;
use protocol::nullifier::Nullifier;
use protocol::transaction::{Transaction, TxId};

use crate::keys::WalletKeys;
use crate::Result;

/// A coin the wallet owns.
#[derive(Clone, Debug)]
pub struct OwnedCoin {
    /// The coin.
    pub coin: Coin,
    /// Its memo.
    pub memo: Memo,
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
}

impl Encodable for OwnedCoin {
    fn write(&self, w: &mut Writer) {
        self.coin.write(w);
        self.memo.write(w);
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
    }

    fn read(r: &mut Reader<'_>) -> protocol::Result<Self> {
        let coin = Coin::read(r)?;
        let memo = Memo::read(r)?;
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
        Ok(Self {
            coin,
            memo,
            position,
            nullifier,
            height,
            spent_at,
            txid,
            spent_by,
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

/// The work a successful decryption does after the cipher check, so it
/// can be repeated on a stand-in coin when the check fails.
///
/// Trial decryption stops at the authentication tag for a coin that is
/// not ours; for ours it goes on to derive the transmission key, the
/// diversified base, the ephemeral key, the commitment and the
/// nullifier. Doing the same on a stand-in coin for every other action
/// makes the cost per action the same either way, so timing does not
/// tell which actions were ours. It equalizes work, not branches: a
/// found coin still costs a vector push.
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

    /// Performs the success path's work and discards it.
    fn work(&self, keys: &WalletKeys) -> Result<()> {
        let diversifier = self.coin.diversifier();
        let _pk_d = keys.incoming_viewing_key().transmission_key(diversifier)?;
        let g_d = diversifier.base()?;
        let _epk = self.coin.esk().public_key(&g_d);
        let _cmx = self.coin.cmx()?;
        let _nf = self.coin.nullifier(keys.nullifier_key())?;
        Ok(())
    }

    /// The compact detection success path's work, for a non-match.
    fn detect(&self, keys: &WalletKeys) -> Result<()> {
        let diversifier = self.coin.diversifier();
        let _pk_d = keys.incoming_viewing_key().transmission_key(diversifier)?;
        let _cmx = self.coin.cmx()?;
        Ok(())
    }
}

/// Decrypts the outputs `block` appends to the tree with `keys`: `tree`
/// lists those transactions in block order. Positions start at
/// `first_position`, the tree size before the
/// block. Spends are every nullifier the block itself reveals. Every action
/// costs the same work whether or not it is ours; see the internal
/// `StandIn` helper.
///
/// # Errors
/// Fails if a decrypted coin cannot derive its nullifier.
pub fn scan_block(
    keys: &WalletKeys,
    block: &Block,
    tree: &[&Transaction],
    first_position: u64,
) -> Result<BlockScan> {
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
            let decrypted = decrypt_coin_with_ivk(
                keys.incoming_viewing_key(),
                keys.receiver_key(),
                body.encrypted_coin(),
                rho,
                body.cmx(),
            );
            let Ok((coin, memo)) = decrypted else {
                stand_in.work(keys)?;
                continue;
            };
            let nullifier = coin.nullifier(keys.nullifier_key())?;
            if coin.value().raw() == 0 {
                continue;
            }
            scan.found.push(OwnedCoin {
                coin,
                memo,
                position,
                nullifier,
                height: block.header().height,
                spent_at: None,
                txid: Some(txid),
                spent_by: None,
            });
        }
    }
    Ok(scan)
}

/// Detects owned coins in one compact block. Produces the same leaves as
/// [`scan_block`] and the same owned coins, except that their memos are
/// empty, since a compact block omits them. Its spent nullifiers are those
/// of its block-order actions. It includes the coinbase, which differs only
/// in dummy spends that never match a wallet coin.
///
/// # Errors
/// Fails if a detected coin cannot derive its nullifier.
pub fn scan_compact_block(
    keys: &WalletKeys,
    block: &CompactBlock,
    first_position: u64,
) -> Result<BlockScan> {
    let mut scan = BlockScan::default();
    let stand_in = StandIn::new(keys)?;
    for action in &block.actions {
        let position =
            first_position.saturating_add(u64::try_from(scan.leaves.len()).unwrap_or(u64::MAX));
        scan.leaves.push(*action.cmx.inner());
        scan.spent.push((action.nullifier, None));
        let rho = Rho::from_nullifier(&action.nullifier)?;
        let detected = detect_coin_with_ivk(
            keys.incoming_viewing_key(),
            keys.receiver_key(),
            &action.kem_ciphertext,
            &action.enc_lead,
            rho,
            &action.cmx,
        );
        let Ok(coin) = detected else {
            stand_in.detect(keys)?;
            continue;
        };
        let nullifier = coin.nullifier(keys.nullifier_key())?;
        if coin.value().raw() == 0 {
            continue;
        }
        scan.found.push(OwnedCoin {
            coin,
            memo: Memo::empty(),
            position,
            nullifier,
            height: block.height,
            spent_at: None,
            txid: None,
            spent_by: None,
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
    fn the_stand_in_does_the_success_path_work_without_failing() {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1)))
                .unwrap();
        let stand_in = StandIn::new(&keys).unwrap();
        stand_in.work(&keys).unwrap();
        assert_eq!(stand_in.coin.value().raw(), 0);
    }
}
