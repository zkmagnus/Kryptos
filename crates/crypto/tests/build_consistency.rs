//! Public deterministic vectors for comparing generic and native release builds.

use crypto::commitment::{
    CoinCommitInputs, CoinCommitTrapdoor, CoinCommitment, ValueCommitTrapdoor, ValueCommitment,
};
use crypto::encoding::{base_from_bytes, base_to_bytes, point_to_bytes, to_hex};
use crypto::hash::{blake2b_short, PIN, TXID};
use crypto::keys::{FullViewingKey, SpendAuthorizingKey};
use crypto::pallas;
use crypto::poseidon;
use crypto::rip1::ExtendedSpendingKey;
use crypto::signature::{RandomizedSigningKey, SpendAuthRandomizer};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn deterministic_crypto_build_vector() -> crypto::Result<()> {
    // Synthetic test material only. Never use this seed for funds.
    let account = ExtendedSpendingKey::account(&[42; 32], 7)?;
    let spending_key = account.spending_key();
    let fvk = FullViewingKey::derive(spending_key)?;
    assert_eq!(
        FullViewingKey::from_bytes(&fvk.to_bytes())?.to_bytes(),
        fvk.to_bytes()
    );
    let diversifier = fvk.diversifier_key().diversifier(9u64.into())?;
    let g_d = diversifier.base()?;
    let pk_d = fvk.incoming_viewing_key()?.transmission_key(&diversifier)?;
    let rho = pallas::Base::from(11u64);
    let psi = pallas::Base::from(13u64);
    let inputs = CoinCommitInputs {
        g_d: &g_d,
        pk_d: pk_d.as_point(),
        value: 123_456_789,
        rho: &rho,
        psi: &psi,
    };
    let commitment = CoinCommitment::commit(
        &inputs,
        &CoinCommitTrapdoor::from_base(pallas::Base::from(17u64)),
    );
    assert_eq!(
        CoinCommitment::from_bytes(&commitment.to_bytes())?,
        commitment
    );
    assert!(CoinCommitment::from_bytes(&[255; 32]).is_err());
    let nullifier = poseidon::nullifier(&fvk.nk().expose(), &rho, &psi, commitment.inner());
    assert_eq!(base_from_bytes(&base_to_bytes(&nullifier))?, nullifier);
    assert_ne!(
        nullifier,
        poseidon::nullifier(&fvk.nk().expose(), &psi, &rho, commitment.inner())
    );
    let value_commitment = ValueCommitment::commit_u64(
        inputs.value,
        &ValueCommitTrapdoor::from_scalar(pallas::Scalar::from(19u64)),
    );
    assert_eq!(
        ValueCommitment::from_bytes(&value_commitment.to_bytes())?,
        value_commitment
    );
    let message = blake2b_short(
        TXID,
        &[b"Rhombus build consistency", &commitment.to_bytes()],
    );
    let ask = SpendAuthorizingKey::derive(spending_key)?;
    let randomizer = SpendAuthRandomizer::from_scalar(pallas::Scalar::from(23u64));
    let signing_key = RandomizedSigningKey::new(&ask, &randomizer)?;
    let signature = signing_key.sign(&mut ChaCha20Rng::seed_from_u64(29), &message);
    signing_key
        .verification_key()
        .verify(&message, &signature)?;
    assert!(signing_key
        .verification_key()
        .verify(b"wrong message", &signature)
        .is_err());

    let digest = blake2b_short(
        PIN,
        &[
            &spending_key.to_bytes(),
            &fvk.to_bytes(),
            diversifier.as_bytes(),
            &point_to_bytes(&g_d),
            &pk_d.to_bytes(),
            &commitment.to_bytes(),
            &base_to_bytes(&nullifier),
            &value_commitment.to_bytes(),
            &message,
            &signature.to_bytes(),
        ],
    );
    eprintln!("crypto build vector: {}", to_hex(&digest));
    // The generator-domain migration in 7a97c456 changed the commitments and
    // signatures in this vector. Restoring just the two old curve domains in
    // an isolated source copy reproduces the former 94d44403... value; see
    // docs/crypto-build-vector.md. Production derivation is unchanged here.
    assert_eq!(
        to_hex(&digest),
        "e1081cf184e5f362183188e288ffcf789ac426b22059076f062b58d3f4f37eaf",
        "canonical crypto outputs changed between builds",
    );
    Ok(())
}

/// Run with `cargo test --release -p crypto --test build_consistency poseidon_cost -- --ignored --nocapture`.
#[test]
#[ignore = "wall-time measurement, not a check"]
fn poseidon_cost() {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    fn measure(label: &str, mut operation: impl FnMut() -> pallas::Base) {
        const BATCH: u32 = 1024;
        let expected = operation();
        let mut samples: [Duration; 7] = std::array::from_fn(|_| {
            let mut result = expected;
            let started = Instant::now();
            for _ in 0..BATCH {
                result = black_box(operation());
            }
            let elapsed = started.elapsed();
            assert_eq!(result, expected);
            elapsed
        });
        samples.sort_unstable();
        let median = samples[3];
        eprintln!(
            "{label}: batch={BATCH}, samples=7, median={median:?}, ns/op={:.1}",
            median.as_nanos() as f64 / f64::from(BATCH),
        );
    }

    // Public fixed inputs; black_box prevents constant folding of the hash.
    let inputs = [11u64, 13, 17, 19].map(pallas::Base::from);
    measure("Poseidon merkle_node", || {
        poseidon::merkle_node(black_box(&inputs[0]), black_box(&inputs[1]))
    });
    measure("Poseidon nullifier", || {
        poseidon::nullifier(
            black_box(&inputs[0]),
            black_box(&inputs[1]),
            black_box(&inputs[2]),
            black_box(&inputs[3]),
        )
    });
}
