use crate::key::*;
use crate::signature::*;
use rand::CryptoRng;
use std::sync::OnceLock;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

pub const SEED_SIZE: usize = 32;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed(pub [u8; SEED_SIZE]);

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Pair {
    pub seed: Seed,
    sk_cache: OnceLock<PrivateKey>,
}

impl Pair {
    pub fn new(seed: &Seed) -> Self {
        Self {
            seed: seed.clone(),
            sk_cache: OnceLock::new(),
        }
    }

    pub fn generate_new<R: CryptoRng>(rng: &mut R) -> (Self, String, Seed) {
        let mut seed_bytes = [0u8; SEED_SIZE];
        rng.fill_bytes(&mut seed_bytes);

        let seed = Seed(seed_bytes);
        let pair = Self::new(&seed);
        (pair, "bls-not-using-bip39".into(), seed)
    }

    fn private(&self) -> &PrivateKey {
        self.sk_cache.get_or_init(|| PrivateKey::new(&self.seed))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.private().sign(msg)
    }

    pub fn pop_prove(&self) -> ProofOfPossession {
        pop_prove(self.private())
    }

    pub fn public(&self) -> PublicKey {
        self.private().public_key()
    }
}
