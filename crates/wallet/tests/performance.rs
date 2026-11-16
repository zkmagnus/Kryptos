//! Repeatable measurements of the real compact scanner, without proof setup.

use std::hint::black_box;
use std::time::{Duration, Instant};

use crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use crypto::keys::SpendingKey;
use crypto::pallas;
use protocol::amount::RawCoin;
use protocol::block::BlockHash;
use protocol::coin::{Coin, RandomSeed, Rho};
use protocol::compact::{CompactAction, CompactBlock};
use protocol::encryption::{encrypt_coin, COMPACT_COIN_LEAD};
use protocol::nullifier::Nullifier;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use wallet::keys::{ScanKeys, WalletKeys};
use wallet::scan::scan_compact_block_with_keys;

type BenchResult<T> = Result<T, Box<dyn std::error::Error>>;

fn fixture(
    owner: &WalletKeys,
    foreign: &WalletKeys,
    owned: [bool; 2],
    last_index: u64,
    rng: &mut ChaCha20Rng,
) -> BenchResult<CompactBlock> {
    let mut actions = Vec::with_capacity(2);
    for (index, is_owned) in owned.into_iter().enumerate() {
        let recipient = if is_owned { owner } else { foreign };
        let address = recipient.address(last_index.into())?;
        let nullifier = Nullifier::from_base(&pallas::Base::from(index as u64 + 1));
        let coin = Coin::new(
            *address.diversifier(),
            *address.pk_d(),
            RawCoin::from_raw(index as u64 + 1)?,
            Rho::from_nullifier(&nullifier)?,
            RandomSeed::random(rng),
        );
        let cmx = coin.cmx()?;
        let cv = ValueCommitment::commit(0, &ValueCommitTrapdoor::random(rng));
        let encrypted = encrypt_coin(&coin, address.kem_key(), None, &cv, rng)?;
        let mut enc_lead = [0; COMPACT_COIN_LEAD];
        enc_lead.copy_from_slice(&encrypted.enc_ciphertext()[..COMPACT_COIN_LEAD]);
        actions.push(CompactAction {
            nullifier,
            cmx,
            kem_ciphertext: encrypted.kem_ciphertext().clone(),
            enc_lead,
        });
    }
    Ok(CompactBlock {
        height: 0,
        hash: BlockHash::ZERO,
        actions,
    })
}

/// Run with `cargo test --release -p wallet --test performance --locked
/// --offline -- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore = "measurement, not a timing assertion"]
fn compact_trial_decryption() -> BenchResult<()> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5248_4f4d);
    let owner = WalletKeys::from_spending_key(SpendingKey::random(&mut rng))?;
    let foreign = WalletKeys::from_spending_key(SpendingKey::random(&mut rng))?;
    for count in [1, 16, 256, 4096] {
        let scan_keys = ScanKeys::new(&owner, 0, count)?;
        for (name, owned, expected) in [
            ("owned", [true, true], 2),
            ("foreign", [false, false], 0),
            ("mixed", [true, false], 1),
        ] {
            // Derivation, encryption, and expected leaves are outside timing.
            let block = fixture(&owner, &foreign, owned, count - 1, &mut rng)?;
            let leaves: Vec<_> = block
                .actions
                .iter()
                .map(|action| *action.cmx.inner())
                .collect();
            let mut samples = [Duration::ZERO; 3];
            for sample in &mut samples {
                let start = Instant::now();
                let scan = black_box(scan_compact_block_with_keys(
                    black_box(&owner),
                    black_box(&scan_keys),
                    black_box(&block),
                    0,
                )?);
                *sample = start.elapsed();
                assert_eq!(scan.found.len(), expected);
                assert_eq!(scan.leaves, leaves);
                assert_eq!(scan.spent.len(), 2);
            }
            samples.sort_unstable();
            eprintln!(
                "compact_scan case={name} address_keys={count} candidates={} outputs=2 samples=3 median_us={}",
                scan_keys.candidate_count(),
                samples[1].as_micros()
            );
        }
    }
    Ok(())
}
