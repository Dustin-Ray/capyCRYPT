use capy_kem::{constants::parameter_sets::KEM_768, fips203::keygen::k_pke_keygen};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KEMPrivateKey {
    pub dk: Vec<u8>,
}

pub struct KEMPublicKey {
    pub rand_bytes: [u8; 32],
    pub ek: Vec<u8>,
}

impl KEMPublicKey {
    pub fn new(&self, rand_bytes: [u8; 32], ek: Vec<u8>) -> Self {
        KEMPublicKey { rand_bytes, ek }
    }
}

pub fn kem_keygen() -> (KEMPublicKey, KEMPrivateKey) {
    let mut rng = thread_rng();
    let mut rand_bytes = [0u8; 32];

    // generate randomness for the KEM
    rng.fill_bytes(&mut rand_bytes);
    let (ek, dk) = k_pke_keygen::<KEM_768>(&rand_bytes);

    (KEMPublicKey { rand_bytes, ek }, KEMPrivateKey { dk })
}
