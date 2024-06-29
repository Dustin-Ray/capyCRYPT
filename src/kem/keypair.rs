use capy_kem::{constants::parameter_sets::KEM_768, fips203::keygen::k_pke_keygen};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

/// Represents a private key for Key Encapsulation Mechanism (KEM).
///
/// This structure holds the private decryption key (`dk`)
/// necessary for the decryption process in KEM.
///
/// ## Fields
/// * `dk: Vec<u8>` - The private decryption key data,
/// essential for decrypting the KEM ciphertext.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KEMPrivateKey {
    pub dk: Vec<u8>,
}

/// Represents a public key for Key Encapsulation Mechanism (KEM).
///
/// This structure holds the public encryption key (`ek`) and a set of random bytes
/// (`rand_bytes`) used to initialize or seed certain operations within the KEM.
/// The public key is used in the encryption process,
/// encapsulating data in such a way that only someone with the
/// corresponding private key can decrypt it.
///
/// ## Fields
/// * `rand_bytes: [u8; 32]` - Random bytes used to seed KEM
/// operations, ensuring the uniqueness and security of the public key.
/// * `ek: Vec<u8>` - The public encryption key data,
/// used to encrypt data in the KEM scheme.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KEMPublicKey {
    pub rand_bytes: [u8; 32],
    pub ek: Vec<u8>,
}

/// Generates a public-private key pair for use with the Key Encapsulation Mechanism (KEM).
///
/// This function interfaces with [`capy_kem`] for partial ML-KEM-768 support.(Partial because
/// the other parameter sets are a work in progress) to generate a compatible key pair.
///
/// It initializes the necessary randomness and calls the library-specific key generation
/// function to produce both encryption and decryption keys.
///
/// ## Returns
/// Returns a tuple containing:
/// * `KEMPublicKey`: Contains the public encryption key and initial random bytes.
/// * `KEMPrivateKey`: Contains the private decryption key.
pub fn kem_keygen() -> (KEMPublicKey, KEMPrivateKey) {
    let mut rng = thread_rng();
    let mut rand_bytes = [0u8; 32];

    // generate randomness for the KEM
    rng.fill_bytes(&mut rand_bytes);
    let (ek, dk) = k_pke_keygen::<KEM_768>(&rand_bytes);

    (KEMPublicKey { rand_bytes, ek }, KEMPrivateKey { dk })
}
