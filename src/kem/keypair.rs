use capy_kem::{
    constants::parameter_sets::KEM_768,
    fips203::keygen::{ml_kem_keygen, KEMPrivateKey, KEMPublicKey},
};

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
    let (ek, dk) = ml_kem_keygen::<KEM_768>();

    (ek, dk)
}
