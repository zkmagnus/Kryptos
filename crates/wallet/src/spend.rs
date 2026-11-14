//! Selecting coins and building a payment.

use protocol::address::RhombusAddress;
use protocol::amount::RawCoin;
use protocol::builder::{Builder, OutputInfo, SpendInfo};
use protocol::consensus::action_class_for;
use protocol::consensus::BranchId;
use protocol::transaction::Transaction;
use rand_core::{CryptoRng, RngCore};
use transaction_proof::ProvingKey;

use crate::scan::OwnedCoin;
use crate::wallet::Wallet;
use crate::{Error, Result};

/// Picks the fewest largest coins covering `amount` for a transaction with
/// `outputs` outputs (recipients plus change).
///
/// # Errors
/// Returns [`Error::InsufficientFunds`] when the coins cannot cover it,
/// or a protocol error if the spends would exceed the largest class.
pub fn select_coins<'a>(
    unspent: &[&'a OwnedCoin],
    amount: RawCoin,
    outputs: usize,
) -> Result<Vec<&'a OwnedCoin>> {
    let mut sorted: Vec<&OwnedCoin> = unspent.to_vec();
    sorted.sort_by_key(|n| core::cmp::Reverse(n.coin.value().raw()));
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for coin in sorted {
        chosen.push(coin);
        total = total.saturating_add(coin.coin.value().raw());
        action_class(chosen.len(), outputs)?;
        if total >= amount.raw() {
            return Ok(chosen);
        }
    }
    let have = total;
    let need = amount.raw();
    Err(Error::InsufficientFunds { have, need })
}

/// The action count of a transaction with `spends` spends and `outputs`
/// outputs. One spend and one output share each action, so the longer side
/// sets the class.
///
/// # Errors
/// Returns a protocol error past the largest class.
fn action_class(spends: usize, outputs: usize) -> Result<usize> {
    Ok(action_class_for(spends.max(outputs).max(2))?)
}

/// Selects inputs for one payment, excluding locked or insufficiently
/// confirmed coins.
fn plan<'a>(
    unspent: &'a [OwnedCoin],
    payment: &Payment,
    fee: RawCoin,
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<Vec<&'a OwnedCoin>> {
    let refs: Vec<&OwnedCoin> = unspent
        .iter()
        .filter(|n| !excluded.contains(&n.position) && n.height <= max_coin_height)
        .collect();
    let needed = payment.amount.checked_add(fee)?;
    select_coins(&refs, needed, 2)
}

/// Finds a stable coin selection and fee, accounting for fee bytes possibly
/// requiring one more input and therefore a larger action class.
fn plan_with_default_fee<'a>(
    unspent: &'a [OwnedCoin],
    payment: &Payment,
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<(Vec<&'a OwnedCoin>, RawCoin)> {
    let mut fee = RawCoin::ZERO;
    for _ in 0..=protocol::consensus::ACTION_CLASSES.len() {
        let chosen = plan(unspent, payment, fee, excluded, max_coin_height)?;
        let actions = action_class(chosen.len(), 2)?;
        let required = Transaction::default_fee_for_actions(actions)?;
        if required == fee {
            return Ok((chosen, fee));
        }
        fee = required;
    }
    Err(Error::Protocol(protocol::Error::InvalidTransaction(
        "default fee selection did not converge",
    )))
}

/// What to pay, to whom
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    /// The recipient.
    pub recipient: RhombusAddress,
    /// The amount.
    pub amount: RawCoin,
}

/// A built transaction and the coins it spends.
#[derive(Clone, Debug)]
pub struct Built {
    /// The transaction, proved and signed.
    pub transaction: Transaction,
    /// Positions of the coins it spends, to set aside until it is mined.
    pub spent: Vec<u64>,
}

/// Builds `payment` from the wallet's unspent coins, returning change to
/// its default address. The anchor is the wallet's current tree root, so
/// the wallet must be scanned up to a recent block first.
///
/// # Errors
/// Fails on insufficient funds or a building error.
pub fn build_payment(
    wallet: &Wallet,
    payment: Payment,
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Transaction> {
    Ok(build_payment_with_options(wallet, payment, pk, branch, &[], u32::MAX, rng)?.transaction)
}

/// Builds one payment while respecting operation locks and confirmation age.
pub fn build_payment_with_options(
    wallet: &Wallet,
    payment: Payment,
    pk: &ProvingKey,
    branch: BranchId,
    excluded: &[u64],
    max_coin_height: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let unspent = spendable_coins(wallet)?;
    let (chosen, fee) = plan_with_default_fee(&unspent, &payment, excluded, max_coin_height)?;
    build_selected(wallet, payment, fee, &chosen, pk, branch, rng)
}

fn spendable_coins(wallet: &Wallet) -> Result<Vec<OwnedCoin>> {
    wallet.unspent()
}

fn build_selected(
    wallet: &Wallet,
    payment: Payment,
    fee: RawCoin,
    chosen: &[&OwnedCoin],
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let keys = wallet.keys();
    let sk = keys.spending_key();
    let amount = payment.amount;
    let positions: Vec<u64> = chosen.iter().map(|n| n.position).collect();
    let (paths, anchor) = wallet.witnesses(&positions)?;
    let mut builder = Builder::new(anchor);
    let mut total = 0u64;
    for (owned, path) in chosen.iter().zip(paths) {
        builder.add_spend(SpendInfo::new(sk.clone(), owned.coin.clone(), path))?;
        total = total.saturating_add(owned.coin.value().raw());
    }
    let ovk = Some(keys.outgoing_viewing_key().clone());
    builder.add_output(OutputInfo::new(
        payment.recipient,
        payment.amount,
        ovk.clone(),
    ))?;
    let change = total
        .checked_sub(amount.raw())
        .and_then(|value| value.checked_sub(fee.raw()))
        .ok_or(protocol::Error::RawCoinOutOfRange)?;
    if change > 0 {
        builder.add_output(OutputInfo::new(
            keys.default_address()?,
            RawCoin::from_raw(change)?,
            ovk,
        ))?;
    }
    let transaction = builder.build_with_fee(fee, pk, branch, rng)?;
    Ok(Built {
        transaction,
        spent: positions,
    })
}

#[cfg(test)]
mod tests {
    use crypto::keys::SpendingKey;
    use crypto::pallas;
    use protocol::amount::RawCoin;
    use protocol::coin::{Coin, RandomSeed, Rho};
    use protocol::nullifier::Nullifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::WalletKeys;

    fn owned(rng: &mut ChaCha20Rng, keys: &WalletKeys, value: u64, position: u32) -> OwnedCoin {
        let coin = Coin::new(
            *keys.default_address().unwrap().diversifier(),
            *keys.default_address().unwrap().pk_d(),
            RawCoin::from_raw(value).unwrap(),
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        let nullifier = Nullifier::from_base(&pallas::Base::from(u64::from(position)));
        OwnedCoin {
            coin,
            position: u64::from(position),
            nullifier,
            height: 1,
            spent_at: None,
            txid: None,
            spent_by: None,
        }
    }

    #[test]
    fn selection_prefers_large_coins_without_a_fee() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let coins = [
            owned(&mut rng, &keys, 100, 0),
            owned(&mut rng, &keys, 5_000_000, 1),
            owned(&mut rng, &keys, 3_000_000, 2),
        ];
        let refs: Vec<&OwnedCoin> = coins.iter().collect();
        let chosen = select_coins(&refs, RawCoin::from_raw(4_000_000).unwrap(), 2).unwrap();
        assert_eq!(chosen.len(), 1, "the largest coin covers the amount");
        assert_eq!(chosen[0].position, 1);

        let chosen = select_coins(&refs, RawCoin::from_raw(6_000_000).unwrap(), 2).unwrap();
        assert_eq!(chosen.len(), 2, "two coins needed");

        let err = select_coins(&refs, RawCoin::from_raw(100_000_000).unwrap(), 2).unwrap_err();
        assert!(matches!(err, Error::InsufficientFunds { .. }));

        // Three recipients plus change need the four-action class even
        // from one coin.
        let chosen = select_coins(&refs, RawCoin::from_raw(1_000).unwrap(), 4).unwrap();
        assert_eq!(chosen.len(), 1);
    }

    fn pay(keys: &WalletKeys, amount: u64) -> Payment {
        Payment {
            recipient: keys.default_address().unwrap(),
            amount: RawCoin::from_raw(amount).unwrap(),
        }
    }

    #[test]
    fn single_payment_selection_uses_fewest_largest_coins() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let coins: Vec<OwnedCoin> = (0..6)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();

        let one = plan(&coins, &pay(&keys, 500_000), RawCoin::ZERO, &[], u32::MAX).unwrap();
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn selection_skips_excluded_and_unconfirmed_coins() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let mut coins: Vec<OwnedCoin> = (0..2)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();
        coins[1].height = 10;
        let payment = pay(&keys, 1_500_000);
        assert!(plan(&coins, &payment, RawCoin::ZERO, &[], u32::MAX).is_ok());
        for (excluded, max_height) in [(&[0][..], u32::MAX), (&[][..], 9)] {
            let err = plan(&coins, &payment, RawCoin::ZERO, excluded, max_height).unwrap_err();
            assert!(matches!(err, Error::InsufficientFunds { .. }));
        }
    }
}
