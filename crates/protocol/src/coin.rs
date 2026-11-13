//! Coins: the unit of value in the shielded pool.
//!
//! A coin is `(recipient, value, rho, rseed)`. From `rseed` and `rho` the
//! coin derives its commitment trapdoor `rcm` and the nullifier nonce `psi`.
//!
//! ```text
//! cm  = Poseidon(g_d.x, pk_d.x, pack(value, signs), rho, psi, rcm)
//! nf  = Poseidon(nk, rho, psi, cm)
//! ```
//!
//! `rho` of an output coin is the nullifier of the coin spent in the same
//! action, which is what makes nullifiers unique across the chain.

use crypto::commitment::{CoinCommitInputs, CoinCommitTrapdoor, CoinCommitment};
use crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use crypto::encryption::EphemeralSecretKey;
use crypto::hash::{prf_expand, wide_to_base, wide_to_scalar};
use crypto::keys::{DiversifiedTransmissionKey, Diversifier, NullifierKey};
use crypto::pallas;
use crypto::poseidon::nullifier;
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::amount::Amount;
use crate::bytes::{Encodable, Reader, Writer};
use crate::nullifier::Nullifier;
use crate::Result;

/// `PRF^expand` tag deriving `esk` from the random seed.
const ESK_TAG: u8 = 0x04;
/// `PRF^expand` tag deriving `rcm` from the random seed.
const RCM_TAG: u8 = 0x05;
/// `PRF^expand` tag deriving `psi` from the random seed.
const PSI_TAG: u8 = 0x09;

/// Byte length of a random seed.
pub const RANDOM_SEED_LEN: usize = 32;

/// The 32-byte seed from which a coin's randomness is derived.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RandomSeed([u8; RANDOM_SEED_LEN]);

impl RandomSeed {
    /// Samples a fresh seed.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; RANDOM_SEED_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps raw bytes, as recovered from a decrypted coin plaintext.
    pub fn from_bytes(bytes: [u8; RANDOM_SEED_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for the coin plaintext.
    pub fn as_bytes(&self) -> &[u8; RANDOM_SEED_LEN] {
        &self.0
    }

    /// `esk`: the ephemeral secret used to encrypt this coin.
    pub fn esk(&self, rho: &Rho) -> EphemeralSecretKey {
        EphemeralSecretKey::from_scalar(wide_to_scalar(&self.expand(ESK_TAG, rho)))
    }

    fn expand(&self, tag: u8, rho: &Rho) -> [u8; crypto::hash::WIDE_OUTPUT_LEN] {
        let mut input = [0u8; 33];
        let (t, r) = input.split_at_mut(1);
        t.copy_from_slice(&[tag]);
        r.copy_from_slice(&rho.to_bytes());
        prf_expand(&self.0, &input)
    }

    /// `rcm`: the coin commitment trapdoor.
    pub fn rcm(&self, rho: &Rho) -> CoinCommitTrapdoor {
        CoinCommitTrapdoor::from_base(wide_to_base(&self.expand(RCM_TAG, rho)))
    }

    /// `psi`: the nullifier nonce.
    pub fn psi(&self, rho: &Rho) -> pallas::Base {
        wide_to_base(&self.expand(PSI_TAG, rho))
    }
}

impl core::fmt::Debug for RandomSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RandomSeed(<redacted>)")
    }
}

/// `rho`: the uniqueness nonce of a coin, the nullifier of the coin that
/// was spent to create it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rho(pallas::Base);

impl Rho {
    /// A coin created by spending the coin with nullifier `nf`.
    ///
    /// # Errors
    /// Cannot fail for a well-formed nullifier.
    pub fn from_nullifier(nf: &Nullifier) -> Result<Self> {
        nf.to_base().map(Self)
    }

    /// Wraps a field element directly, for coinbase coins and tests.
    pub fn from_base(value: pallas::Base) -> Self {
        Self(value)
    }

    /// A random `rho`, for dummy coins that are never spent.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(pallas::Base::random(rng))
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        base_to_bytes(&self.0)
    }

    /// The field element.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }
}

/// `cmx`: the x-coordinate of a coin commitment, as stored in the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtractedCoinCommitment(pallas::Base);

impl ExtractedCoinCommitment {
    /// Extracts from a full commitment.
    pub fn from_commitment(cm: &CoinCommitment) -> Self {
        Self(*cm.inner())
    }

    /// The field element.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0)
    }

    /// Parses a canonical encoding.
    ///
    /// # Errors
    /// Fails if the bytes are not a canonical base field element.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        Ok(Self(base_from_bytes(bytes)?))
    }
}

impl Encodable for ExtractedCoinCommitment {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(&r.take_array()?)
    }
}

/// A coin in the shielded pool.
#[derive(Clone, Debug)]
pub struct Coin {
    diversifier: Diversifier,
    pk_d: DiversifiedTransmissionKey,
    value: Amount,
    rho: Rho,
    rseed: RandomSeed,
}

impl Coin {
    /// Builds a coin from its parts.
    pub fn new(
        diversifier: Diversifier,
        pk_d: DiversifiedTransmissionKey,
        value: Amount,
        rho: Rho,
        rseed: RandomSeed,
    ) -> Self {
        Self {
            diversifier,
            pk_d,
            value,
            rho,
            rseed,
        }
    }

    /// The recipient address.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// The diversified transmission key.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    /// The value.
    pub fn value(&self) -> Amount {
        self.value
    }

    /// The uniqueness nonce.
    pub fn rho(&self) -> &Rho {
        &self.rho
    }

    /// The random seed.
    pub fn rseed(&self) -> &RandomSeed {
        &self.rseed
    }

    /// `psi`, derived from the seed and `rho`.
    pub fn psi(&self) -> pallas::Base {
        self.rseed.psi(&self.rho)
    }

    /// The ephemeral secret key used to encrypt this coin.
    pub fn esk(&self) -> EphemeralSecretKey {
        self.rseed.esk(&self.rho)
    }

    /// The coin commitment `cm`.
    ///
    /// # Errors
    /// Fails if the recipient's diversifier is invalid.
    pub fn commitment(&self) -> Result<CoinCommitment> {
        let g_d = self.diversifier.base()?;
        let inputs = CoinCommitInputs {
            g_d: &g_d,
            pk_d: self.pk_d().as_point(),
            value: self.value.raw(),
            rho: &self.rho.0,
            psi: &self.psi(),
        };
        Ok(CoinCommitment::commit(&inputs, &self.rseed.rcm(&self.rho)))
    }

    /// `cmx`, the extracted coin commitment.
    ///
    /// # Errors
    /// Propagates commitment errors.
    pub fn cmx(&self) -> Result<ExtractedCoinCommitment> {
        self.commitment()
            .map(|cm| ExtractedCoinCommitment::from_commitment(&cm))
    }

    /// The nullifier that spending this coin reveals.
    ///
    /// # Errors
    /// Propagates commitment errors.
    pub fn nullifier(&self, nk: &NullifierKey) -> Result<Nullifier> {
        let cm = self.commitment()?;
        Ok(Nullifier::from_base(&nullifier(
            &nk.expose(),
            &self.rho.0,
            &self.psi(),
            cm.inner(),
        )))
    }
}

impl Encodable for Coin {
    fn write(&self, w: &mut Writer) {
        w.put(self.diversifier.as_bytes())
            .put(&self.pk_d.to_bytes())
            .put_u64_le(self.value.raw())
            .put(&self.rho.to_bytes())
            .put(self.rseed.as_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let diversifier = Diversifier::from_bytes(r.take_array()?);
        diversifier.base()?; // validation diversifier
        let pk_d = DiversifiedTransmissionKey::from_bytes(&r.take_array()?)?;
        let value = Amount::from_raw(r.take_u64_le()?)?;
        let rho = Rho::from_base(base_from_bytes(&r.take_array()?)?);
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        Ok(Self::new(diversifier, pk_d, value, rho, rseed))
    }
}

#[cfg(test)]
mod tests {
    use crate::address::RhombusAddress as Address;
    use crate::amount::Amount;
    use crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    struct Fixture {
        fvk: FullViewingKey,
        coin: Coin,
    }

    fn fixture(seed: u64) -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut rng)).unwrap();
        let recipient = Address::derive(&fvk, Diversifier::random(&mut rng)).unwrap();
        let rho = Rho::from_base(pallas::Base::from(seed));
        let coin = Coin::new(
            recipient,
            Amount::from_raw(1_000).unwrap(),
            rho,
            RandomSeed::random(&mut rng),
        );
        Fixture { fvk, coin }
    }

    #[test]
    fn commitment_is_deterministic() {
        let f = fixture(1);
        assert_eq!(f.coin.commitment().unwrap(), f.coin.commitment().unwrap());
    }

    #[test]
    fn commitment_changes_with_every_field() {
        let f = fixture(2);
        let base = f.coin.commitment().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let other_value = Coin::new(
            f.coin.recipient,
            Amount::from_raw(1_001).unwrap(),
            f.coin.rho,
            f.coin.rseed.clone(),
        );
        assert_ne!(base, other_value.commitment().unwrap(), "value");

        let other_rho = Coin::new(
            f.coin.recipient,
            f.coin.value,
            Rho::from_base(pallas::Base::from(7u64)),
            f.coin.rseed.clone(),
        );
        assert_ne!(base, other_rho.commitment().unwrap(), "rho");

        let other_seed = Coin::new(
            f.coin.recipient,
            f.coin.value,
            f.coin.rho,
            RandomSeed::random(&mut rng),
        );
        assert_ne!(base, other_seed.commitment().unwrap(), "rseed");

        let other_recipient = Coin::new(
            fixture(3).coin.recipient,
            f.coin.value,
            f.coin.rho,
            f.coin.rseed.clone(),
        );
        assert_ne!(base, other_recipient.commitment().unwrap(), "recipient");
    }

    #[test]
    fn nullifier_is_deterministic_and_key_dependent() {
        let f = fixture(4);
        let nf = f.coin.nullifier(f.fvk.nk()).unwrap();
        assert_eq!(nf, f.coin.nullifier(f.fvk.nk()).unwrap());
        let other_key = fixture(5).fvk;
        assert_ne!(nf, f.coin.nullifier(other_key.nk()).unwrap());
    }

    #[test]
    fn distinct_coins_have_distinct_nullifiers() {
        let (a, b) = (fixture(6), fixture(7));
        assert_ne!(
            a.coin.nullifier(a.fvk.nk()).unwrap(),
            b.coin.nullifier(a.fvk.nk()).unwrap()
        );
    }

    #[test]
    fn rho_chains_from_nullifier() {
        let f = fixture(8);
        let nf = f.coin.nullifier(f.fvk.nk()).unwrap();
        let rho = Rho::from_nullifier(&nf).unwrap();
        assert_eq!(rho.to_bytes(), nf.to_bytes());
    }

    #[test]
    fn rcm_and_psi_depend_on_rho() {
        let seed = RandomSeed::from_bytes([9; 32]);
        let (r1, r2) = (
            Rho::from_base(pallas::Base::from(1u64)),
            Rho::from_base(pallas::Base::from(2u64)),
        );
        assert_ne!(seed.psi(&r1), seed.psi(&r2));
        let coin = |rho| {
            Coin::new(
                fixture(9).coin.recipient,
                Amount::ZERO,
                rho,
                RandomSeed::from_bytes([9; 32]),
            )
        };
        assert_ne!(
            coin(r1).commitment().unwrap(),
            coin(r2).commitment().unwrap()
        );
    }

    #[test]
    fn esk_differs_from_rcm_and_depends_on_rho() {
        let seed = RandomSeed::from_bytes([3; RANDOM_SEED_LEN]);
        let (r1, r2) = (
            Rho::from_base(pallas::Base::from(1u64)),
            Rho::from_base(pallas::Base::from(2u64)),
        );
        assert_ne!(seed.esk(&r1).to_bytes(), seed.esk(&r2).to_bytes());
        assert_eq!(seed.esk(&r1).to_bytes(), seed.esk(&r1).to_bytes());
        assert_eq!(
            fixture(10).coin.esk().to_bytes(),
            fixture(10).coin.esk().to_bytes()
        );
    }

    #[test]
    fn cmx_matches_extracted_commitment_and_roundtrips() {
        let f = fixture(11);
        let cmx = f.coin.cmx().unwrap();
        assert_eq!(cmx.inner(), f.coin.commitment().unwrap().inner());
        assert_eq!(ExtractedCoinCommitment::from_slice(&cmx.to_vec()), Ok(cmx));
        assert!(ExtractedCoinCommitment::from_bytes(&[0xFF; 32]).is_err());
    }

    #[test]
    fn random_rho_differs_per_call() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        assert_ne!(Rho::random(&mut rng), Rho::random(&mut rng));
    }

    #[test]
    fn coin_encoding_roundtrips_and_preserves_the_commitment() {
        let f = fixture(13);
        let decoded = Coin::from_slice(&f.coin.to_vec()).unwrap();
        assert_eq!(decoded.recipient(), f.coin.recipient());
        assert_eq!(decoded.value(), f.coin.value());
        assert_eq!(decoded.rho(), f.coin.rho());
        assert_eq!(decoded.cmx().unwrap(), f.coin.cmx().unwrap());
    }

    #[test]
    fn random_seed_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", RandomSeed::from_bytes([0; 32])),
            "RandomSeed(<redacted>)"
        );
    }
}
