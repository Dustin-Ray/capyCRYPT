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
    fn kem_encrypt(&mut self, key: &KEMPublicKey, d: &SecParam) -> Result<(), OperationError>;
    fn kem_decrypt(&mut self, key: &KEMPrivateKey) -> Result<(), OperationError>;
}

impl KEMEncryptable for Message {
    fn kem_encrypt(&mut self, key: &KEMPublicKey, d: &SecParam) -> Result<(), OperationError> {
        self.d = Some(*d);

        let mut rng = thread_rng();
        let mut secret = [0_u8; 32];

        // generate a random secret to be used as the shared seed
        rng.fill_bytes(&mut secret);

        let c = k_pke_encrypt::<KEM_768>(&secret, &key.ek, &key.rand_bytes);
        self.kem_ciphertext = Some(c);

        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.extend_from_slice(&secret);

        let ke_ka = kmac_xof(&ke_ka, &[], 1024, "S", d);
        let (ke, ka) = ke_ka.split_at(64);

        self.digest = kmac_xof(ka, &self.msg, 512, "KEMKA", d);

        let m = kmac_xof(ke, &[], self.msg.len() * 8, "KEMKE", d);
        xor_bytes(&mut self.msg, &m);

        self.sym_nonce = Some(z);
        Ok(())
    }

    fn kem_decrypt(&mut self, key: &KEMPrivateKey) -> Result<(), OperationError> {
        let ciphertext = self
            .kem_ciphertext
            .as_ref()
            .ok_or(OperationError::EmptyDecryptionError)?;

        let dec = k_pke_decrypt::<KEM_768>(&key.dk, ciphertext);

        let d = self
            .d
            .as_ref()
            .ok_or(OperationError::SecurityParameterNotSet)?;

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

        self.op_result = if self.digest == new_t {
            Ok(())
        } else {
            xor_bytes(&mut self.msg, &m);
            Err(OperationError::SHA3DecryptionFailure)
        };

        Ok(())
    }
}
