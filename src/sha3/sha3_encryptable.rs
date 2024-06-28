use crate::{
    sha3::aux_functions::byte_utils::{get_random_bytes, xor_bytes},
    Message, OperationError, SecParam, SpongeEncryptable,
};

use super::shake_functions::kmac_xof;

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
    /// ## Usage:
    /// ```
    /// use capycrypt::{
    ///     Message,
    ///     SpongeEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}},
    ///     SecParam::D512,
    /// };
    /// use capycrypt::SecParam;
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.sha3_encrypt(&pw, &D512);
    /// // Decrypt the data
    /// msg.sha3_decrypt(&pw);
    /// // Verify successful operation
    /// assert!(msg.sha3_decrypt(&pw).is_ok(), "Decryption Failure");
    /// ```
    fn sha3_encrypt(&mut self, pw: &[u8], d: &SecParam) -> Result<(), OperationError> {
        self.d = Some(*d);
        let z = get_random_bytes(512);

        let mut ke_ka = z.clone();
        ke_ka.extend_from_slice(pw);

        let ke_ka = kmac_xof(&ke_ka, &[], 1024, "S", d)?;
        let (ke, ka) = ke_ka.split_at(64);

        self.digest = kmac_xof(ka, &self.msg, 512, "SKA", d);

        let m = kmac_xof(ke, &[], (self.msg.len() * 8) as u64, "SKE", d)?;
        xor_bytes(&mut self.msg, &m);

        self.sym_nonce = Some(z);
        Ok(())
    }
    /// # Symmetric Decryption
    /// Decrypts a [`Message`] (z, c, t) under passphrase pw.
    /// ## Assumes:
    /// * well-formed encryption
    /// * Some(Message.t)
    /// * Some(Message.z)
    /// ## Replaces:
    /// * `Message.data` with result of decryption.
    /// * `Message.op_result` with result of comparision of `Message.t` == keyed hash of decryption.
    /// ## Algorithm:
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * m ← kmac_xof(ke, “”, |c|, “SKE”) ⊕ c
    /// * t’ ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &[u8]`: decryption password, can be blank
    /// ## Usage:
    /// ```
    /// use capycrypt::{
    ///     Message,
    ///     SpongeEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}},
    ///     SecParam::D512,
    /// };
    /// use capycrypt::SecParam;
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.sha3_encrypt(&pw, &D512);
    /// // Decrypt the data
    /// msg.sha3_decrypt(&pw);
    /// // Verify successful operation
    /// assert!(msg.sha3_decrypt(&pw).is_ok(), "Decryption Failure");
    /// ```
    fn sha3_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError> {
        let d = self
            .d
            .as_ref()
            .ok_or(OperationError::SecurityParameterNotSet)?;

        let mut z_pw = self
            .sym_nonce
            .as_ref()
            .ok_or(OperationError::SymNonceNotSet)?
            .clone();
        z_pw.extend_from_slice(pw);

        let ke_ka = kmac_xof(&z_pw, &[], 1024, "S", d)?;
        let (ke, ka) = ke_ka.split_at(64);

        let m = kmac_xof(ke, &[], (self.msg.len() * 8) as u64, "SKE", d)?;

        xor_bytes(&mut self.msg, &m);

        let new_t = kmac_xof(ka, &self.msg, 512, "SKA", d)?;

        self.op_result = if self
            .digest
            .as_ref()
            .map_or(false, |digest| digest == &new_t)
        {
            Ok(())
        } else {
            xor_bytes(&mut self.msg, &m);
            Err(OperationError::SHA3DecryptionFailure)
        };

        Ok(())
    }
}
