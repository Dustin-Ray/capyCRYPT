use super::shake_functions::kmac_xof;
use crate::{
    sha3::aux_functions::byte_utils::{get_random_bytes, xor_bytes},
    Message, OperationError, SecParam,
};

pub trait SpongeEncryptable {
    fn sha3_encrypt(&mut self, pw: &[u8], d: SecParam);
    fn sha3_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError>;
}

impl SpongeEncryptable for Message {
    /// # Symmetric Encryption
    /// Encrypts a [`Message`] m symmetrically under passphrase pw.
    /// ## Replaces:
    /// * `Message.data` with result of encryption.
    /// * `Message.t` with keyed hash of plaintext.
    /// * `Message.sym_nonce` with z, as defined below.
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * z ← Random(512)
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * c ← kmac_xof(ke, “”, |m|, “SKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &[u8]`: symmetric encryption key, can be blank but shouldnt be
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    fn sha3_encrypt(&mut self, pw: &[u8], d: SecParam) {
        self.d = Some(d);
        let z = get_random_bytes(512);

        let mut ke_ka = z.clone();
        ke_ka.extend_from_slice(pw);

        let ke_ka = kmac_xof(&ke_ka, &[], 1024, "S", d);
        let (ke, ka) = ke_ka.split_at(64);

        self.digest = kmac_xof(ka, &self.msg, 512, "SKA", d);

        let m = kmac_xof(ke, &[], self.msg.len() * 8, "SKE", d);
        xor_bytes(&mut self.msg, &m);

        self.sym_nonce = Some(z);
    }

    /// # Symmetric Decryption
    /// Decrypts a [`Message`] (z, c, t) under passphrase pw.
    /// ## Replaces:
    /// * `Message.data` with result of decryption.
    /// * `Message.op_result` with result of comparision of `Message.t` == keyed hash of decryption.
    /// ## Algorithm:
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * m ← kmac_xof(ke, “”, |c|, “SKE”) ⊕ c
    /// * t’ ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &[u8]`: decryption password, can be blank
    fn sha3_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError> {
        let d = self.d.ok_or(OperationError::SecurityParameterNotSet)?;

        let mut z_pw = self
            .sym_nonce
            .as_ref()
            .ok_or(OperationError::SymNonceNotSet)?
            .clone();
        z_pw.extend_from_slice(pw);

        let ke_ka = kmac_xof(&z_pw, &[], 1024, "S", d);
        let (ke, ka) = ke_ka.split_at(64);

        let m = kmac_xof(ke, &[], self.msg.len() * 8, "SKE", d);

        xor_bytes(&mut self.msg, &m);

        let new_t = kmac_xof(ka, &self.msg, 512, "SKA", d);

        if self.digest == new_t {
            Ok(())
        } else {
            xor_bytes(&mut self.msg, &m);
            Err(OperationError::SHA3DecryptionFailure)
        }
    }
}
