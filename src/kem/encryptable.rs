use crate::{
    sha3::{
        aux_functions::byte_utils::{get_random_bytes, xor_bytes},
        shake_functions::kmac_xof,
    },
    Message, OperationError, SecParam,
};
use capy_kem::{
    constants::parameter_sets::KEM_768,
    fips203::{decrypt::k_pke_decrypt, encrypt::k_pke_encrypt},
};
use rand::{thread_rng, RngCore};

use super::keypair::{KEMPrivateKey, KEMPublicKey};

pub trait KEMEncryptable {
    fn kem_encrypt(&mut self, key: &KEMPublicKey, d: SecParam);
    fn kem_decrypt(&mut self, key: &KEMPrivateKey) -> Result<(), OperationError>;
}

impl KEMEncryptable for Message {
    /// # Key Encapsulation Mechanism (KEM) Encryption
    /// Encrypts a [`Message`] symmetrically under a KEM public key 𝑉. The KEM keys
    /// are used to derive a shared secret which seeds the sponge, and is then
    /// subsequently used for symmetric encryptions.
    /// ## Replaces:
    /// * `Message.kem_ciphertext` with the result of encryption using KEM public key 𝑉.
    /// * `Message.digest` with the keyed hash of the message using components derived from the encryption process.
    /// * `Message.sym_nonce` with random bytes 𝑧.
    /// ## Algorithm:
    /// * Generate a random secret.
    /// * Encrypt the secret using the KEM public key 𝑉 to generate
    /// shared secret.
    /// * Generate a random nonce 𝑧
    /// * (ke || ka) ← kmac_xof(𝑧 || secret, "", 1024, "S")
    /// * 𝑐 ← kmac_xof(ke, "", |m|, "SKE") ⊕ m
    /// * t ← kmac_xof(ka, m, 512, "SKA")
    /// ## Arguments:
    /// * `key: &KEMPublicKey`: The public key 𝑉 used for encryption.
    /// * `d: SecParam`: Security parameters defining the strength of cryptographic operations.
    fn kem_encrypt(&mut self, key: &KEMPublicKey, d: SecParam) {
        self.d = Some(d);

        let mut rng = thread_rng();
        let secret = &mut [0_u8; 32];

        // generate a random secret to be used as the shared seed
        rng.fill_bytes(secret);

        let c = k_pke_encrypt::<KEM_768>(secret, &key.ek, &key.rand_bytes);
        self.kem_ciphertext = Some(c);

        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.extend_from_slice(secret);

        let ke_ka = kmac_xof(&ke_ka, &[], 1024, "S", d);
        let (ke, ka) = ke_ka.split_at(64);

        self.digest = kmac_xof(ka, &self.msg, 512, "KEMKA", d);

        let m = kmac_xof(ke, &[], self.msg.len() * 8, "KEMKE", d);
        xor_bytes(&mut self.msg, &m);

        self.sym_nonce = Some(z);
    }

    /// # Key Encapsulation Mechanism (KEM) Decryption
    /// Decrypts a [`Message`] using a KEM private key.
    /// ## Replaces:
    /// * `Message.msg` with the result of decryption.
    /// * `Message.op_result` with the result of the comparison of the stored and computed message digests.
    /// ## Algorithm:
    /// * Retrieve the KEM ciphertext and decrypt it using the KEM private key to obtain the decrypted secret.
    /// * Use the stored nonce 𝑧 and decrypted secret to derive two keys (ke and ka) using `kmac_xof`.
    /// * m ← kmac_xof(ke, "", |c|, "SKE") ⊕ c
    /// * t′ ← kmac_xof(ka, m, 512, "SKA")
    /// ## Arguments:
    /// * `key: &KEMPrivateKey`: The private key used for decryption.
    fn kem_decrypt(&mut self, key: &KEMPrivateKey) -> Result<(), OperationError> {
        let ciphertext = self
            .kem_ciphertext
            .as_ref()
            .ok_or(OperationError::EmptyDecryptionError)?;
        let dec = k_pke_decrypt::<KEM_768>(&key.dk, ciphertext);

        let d = self.d.ok_or(OperationError::SecurityParameterNotSet)?;

        let mut z_pw = self
            .sym_nonce
            .as_ref()
            .ok_or(OperationError::SymNonceNotSet)?
            .clone();
        z_pw.extend_from_slice(&dec);

        let ke_ka = kmac_xof(&z_pw, &[], 1024, "S", d);
        let (ke, ka) = ke_ka.split_at(64);

        let m = kmac_xof(ke, &[], self.msg.len() * 8, "KEMKE", d);
        xor_bytes(&mut self.msg, &m);

        let new_t = kmac_xof(ka, &self.msg, 512, "KEMKA", d);

        if self.digest == new_t {
            Ok(())
        } else {
            xor_bytes(&mut self.msg, &m);
            Err(OperationError::SHA3DecryptionFailure)
        }
    }
}
