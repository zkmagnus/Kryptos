//! Selecting coins and building a payment.

use protocol::address::RhombusAddress;
use protocol::amount::RawCoin;
use protocol::builder::{Builder, OutputInfo, SpendInfo};
use protocol::consensus::action_class_for;
use protocol::consensus::{BranchId, MAX_ACTIONS};
use protocol::fee::FeeOpening;
use protocol::memo::Memo;
use protocol::transaction::Transaction;
use rand_core::{CryptoRng, RngCore};
use systemcall_proof::ProvingKey;

use crate::scan::OwnedCoin;
use crate::wallet::Wallet;
use crate::{Error, Result};

/// Most recipients one transaction can pay: one action is kept for the
/// change output.
pub const MAX_RECIPIENTS: usize = MAX_ACTIONS - 1;

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

/// The sum paid to every recipient.
///
/// # Errors
/// Returns a protocol error if the sum overflows the money range.
fn total(payments: &[Payment]) -> Result<RawCoin> {
    Ok(payments
        .iter()
        .try_fold(RawCoin::ZERO, |acc, p| acc.checked_add(p.amount))?)
}

/// Transaction shape and input count for a payment, without proving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    /// Coins the payment would spend.
    pub spends: usize,
    /// Actions in the transaction, after padding to a class.
    pub actions: usize,
}

/// The coins `payments` would spend from `unspent`, skipping `excluded`
/// positions and coins above `max_coin_height`. Change adds
/// one output. [`build_payments`] and [`quote_payments`] both use this, so
/// a quote matches the transaction built from the same coins.
///
/// # Errors
/// [`Error::TooManyRecipients`] past the limit, and
/// [`Error::InsufficientFunds`] when the free coins cannot cover it.
fn plan<'a>(
    unspent: &'a [OwnedCoin],
    payments: &[Payment],
    fee: RawCoin,
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<Vec<&'a OwnedCoin>> {
    if payments.is_empty() || payments.len() > MAX_RECIPIENTS {
        return Err(Error::TooManyRecipients(MAX_RECIPIENTS));
    }
    let refs: Vec<&OwnedCoin> = unspent
        .iter()
        .filter(|n| !excluded.contains(&n.position) && n.height <= max_coin_height)
        .collect();
    let needed = total(payments)?.checked_add(fee)?;
    select_coins(&refs, needed, payments.len().saturating_add(1))
}

/// The shape `payments` would have if built now from the
/// wallet's unspent coins, with the same selection as [`build_payments`].
/// Coins can arrive or be set aside before the payment is built, so this
/// is exact for the wallet's current state only.
///
/// # Errors
/// As [`build_payments`], except that it needs no spending key.
pub fn quote_payments(
    wallet: &Wallet,
    payments: &[Payment],
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<Quote> {
    let unspent = wallet.unspent()?;
    let (chosen, _) = plan_with_default_fee(&unspent, payments, excluded, max_coin_height)?;
    Ok(Quote {
        spends: chosen.len(),
        actions: action_class(chosen.len(), payments.len().saturating_add(1))?,
    })
}

/// Finds a stable coin selection and fee, accounting for fee bytes possibly
/// requiring one more input and therefore a larger action class.
fn plan_with_default_fee<'a>(
    unspent: &'a [OwnedCoin],
    payments: &[Payment],
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<(Vec<&'a OwnedCoin>, RawCoin)> {
    let mut fee = RawCoin::ZERO;
    for _ in 0..=protocol::consensus::ACTION_CLASSES.len() {
        let chosen = plan(unspent, payments, fee, excluded, max_coin_height)?;
        let actions = action_class(chosen.len(), payments.len().saturating_add(1))?;
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

#[cfg(test)]
fn quote_from(
    unspent: &[OwnedCoin],
    payments: &[Payment],
    excluded: &[u64],
    max_coin_height: u32,
) -> Result<Quote> {
    let (chosen, _) = plan_with_default_fee(unspent, payments, excluded, max_coin_height)?;
    Ok(Quote {
        spends: chosen.len(),
        actions: action_class(chosen.len(), payments.len().saturating_add(1))?,
    })
}

/// What to pay, to whom, with which memo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    /// The recipient.
    pub recipient: RhombusAddress,
    /// The amount.
    pub amount: RawCoin,
    /// The memo.
    pub memo: Memo,
}

/// A built transaction and the coins it spends.
#[derive(Clone, Debug)]
pub struct Built {
    /// The transaction, proved and signed.
    pub transaction: Transaction,
    /// Fee opening to send as node-only relay metadata.
    pub fee_opening: FeeOpening,
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
    Ok(build_payments(wallet, &[payment], pk, branch, &[], u32::MAX, rng)?.transaction)
}

/// Builds a payment with an explicit private fee amount.
pub fn build_payment_with_fee(
    wallet: &Wallet,
    payment: Payment,
    fee: RawCoin,
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Transaction> {
    Ok(
        build_payments_with_fee(wallet, &[payment], fee, pk, branch, &[], u32::MAX, rng)?
            .transaction,
    )
}

/// Builds one transaction paying every recipient in `payments`, at most
/// [`MAX_RECIPIENTS`], from the wallet's unspent coins other than those
/// at `excluded` positions (coins set aside for pending operations) and
/// those received above `max_coin_height` (too few confirmations).
/// Change goes to the wallet's default address. The default fee is one raw
/// unit per encoded transaction byte.
///
/// # Errors
/// Returns [`Error::TooManyRecipients`] past the limit and
/// [`Error::InsufficientFunds`] when the free coins cannot cover it.
pub fn build_payments(
    wallet: &Wallet,
    payments: &[Payment],
    pk: &ProvingKey,
    branch: BranchId,
    excluded: &[u64],
    max_coin_height: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let unspent = spendable_coins(wallet)?;
    let (chosen, fee) = plan_with_default_fee(&unspent, payments, excluded, max_coin_height)?;
    build_selected(wallet, payments, fee, &chosen, pk, branch, rng)
}

/// Builds a batched payment and returns change after subtracting the private
/// fee amount. The fee opening is returned in relay metadata.
pub fn build_payments_with_fee(
    wallet: &Wallet,
    payments: &[Payment],
    fee: RawCoin,
    pk: &ProvingKey,
    branch: BranchId,
    excluded: &[u64],
    max_coin_height: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let unspent = spendable_coins(wallet)?;
    let chosen = plan(&unspent, payments, fee, excluded, max_coin_height)?;
    build_selected(wallet, payments, fee, &chosen, pk, branch, rng)
}

fn spendable_coins(wallet: &Wallet) -> Result<Vec<OwnedCoin>> {
    wallet.unspent()
}

fn build_selected(
    wallet: &Wallet,
    payments: &[Payment],
    fee: RawCoin,
    chosen: &[&OwnedCoin],
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let keys = wallet.keys();
    let sk = keys.spending_key();
    let amount = total(payments)?;
    let positions: Vec<u64> = chosen.iter().map(|n| n.position).collect();
    let (paths, anchor) = wallet.witnesses(&positions)?;
    let mut builder = Builder::new(anchor);
    let mut total = 0u64;
    for (owned, path) in chosen.iter().zip(paths) {
        builder.add_spend(SpendInfo::new(sk.clone(), owned.coin.clone(), path))?;
        total = total.saturating_add(owned.coin.value().raw());
    }
    let ovk = Some(keys.outgoing_viewing_key().clone());
    for payment in payments {
        builder.add_output(OutputInfo::new(
            payment.recipient.clone(),
            payment.amount,
            payment.memo.clone(),
            ovk.clone(),
        ))?;
    }
    let change = total
        .checked_sub(amount.raw())
        .and_then(|value| value.checked_sub(fee.raw()))
        .ok_or(protocol::Error::RawCoinOutOfRange)?;
    if change > 0 {
        builder.add_output(OutputInfo::new(
            keys.default_address()?,
            RawCoin::from_raw(change)?,
            Memo::empty(),
            ovk,
        ))?;
    }
    let (transaction, fee_opening) = builder.build_with_fee_opening(fee, pk, branch, rng)?;
    Ok(Built {
        transaction,
        fee_opening,
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
            keys.default_address().unwrap(),
            RawCoin::from_raw(value).unwrap(),
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        let nullifier = Nullifier::from_base(&pallas::Base::from(u64::from(position)));
        OwnedCoin {
            coin,
            memo: Memo::empty(),
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
            memo: Memo::empty(),
        }
    }

    #[test]
    fn quotes_follow_the_coins_selection_would_spend() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let coins: Vec<OwnedCoin> = (0..6)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();

        let one = quote_from(&coins, &[pay(&keys, 500_000)], &[], u32::MAX).unwrap();
        assert_eq!((one.spends, one.actions), (1, 2));

        // Five small coins outgrow the two-action class the recipient
        // count alone suggests, but add no monetary fee.
        let many = quote_from(&coins, &[pay(&keys, 4_500_000)], &[], u32::MAX).unwrap();
        assert_eq!((many.spends, many.actions), (5, 8));
    }

    #[test]
    fn quotes_skip_excluded_and_unconfirmed_coins() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let mut coins: Vec<OwnedCoin> = (0..2)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();
        coins[1].height = 10;
        let payment = [pay(&keys, 1_500_000)];
        assert!(quote_from(&coins, &payment, &[], u32::MAX).is_ok());
        for (excluded, max_height) in [(&[0][..], u32::MAX), (&[][..], 9)] {
            let err = quote_from(&coins, &payment, excluded, max_height).unwrap_err();
            assert!(matches!(err, Error::InsufficientFunds { .. }));
        }
    }

    #[test]
    fn quotes_reject_empty_and_oversized_recipient_lists() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let coins = [owned(&mut rng, &keys, 1_000_000, 0)];
        let too_many = vec![pay(&keys, 1); MAX_RECIPIENTS + 1];
        for payments in [&[][..], &too_many[..]] {
            let err = quote_from(&coins, payments, &[], u32::MAX).unwrap_err();
            assert!(matches!(err, Error::TooManyRecipients(_)));
        }
    }
}
