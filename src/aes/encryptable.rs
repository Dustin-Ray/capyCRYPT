use crate::{
    aes::aes_functions::{apply_pcks7_padding, remove_pcks7_padding, xor_blocks, AES},
    sha3::{aux_functions::byte_utils::get_random_bytes, shake_functions::kmac_xof},
    Message, OperationError, SecParam,
};
use rayon::prelude::*;

pub trait AesEncryptable {
    fn aes_encrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_decrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_encrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_decrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError>;
}

impl AesEncryptable for Message {
    /// # Symmetric Encryption using AES in CBC Mode
    /// Encrypts a [`Message`] using the AES algorithm in CBC (Cipher Block Chaining) mode.
    /// For more information refer to: NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of encryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// * `Message.sym_nonce` with the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Random(16)
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * C1 = encrypt_block(P1 ⊕ IV)
    /// * Cj = encrypt_block(Pj ⊕ Cj-1) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &Vec<u8>`: symmetric encryption key.
    fn aes_encrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = get_random_bytes(16);
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256)?;
        let ke = &ke_ka[..key.len()].to_vec(); // Encryption Key
        let ka = &ke_ka[key.len()..].to_vec(); // Authentication Key

        self.digest = kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256);
        self.sym_nonce = Some(iv.clone());

        let key_schedule = AES::new(ke);

        apply_pcks7_padding(&mut self.msg);

        for block_index in (0..self.msg.len()).step_by(16) {
            xor_blocks(
                &mut self.msg[block_index..],
                self.sym_nonce.as_mut().unwrap(),
            );
            AES::encrypt_block(&mut self.msg, block_index, &key_schedule.round_key);
            *self.sym_nonce.as_mut().unwrap() = self.msg[block_index..block_index + 16].to_vec();
        }

        self.sym_nonce = Some(iv);
        Ok(())
    }

    /// # Symmetric Decryption using AES in CBC Mode
    /// Decrypts a [`Message`] using the AES algorithm in CBC (Cipher Block Chaining) mode.
    /// For more information refer to: NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of decryption.
    /// * `Message.op_result` with the result of verification against the keyed hash.
    /// * `Message.sym_nonce` is used as the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Symmetric nonce (IV)
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * P1 = decrypt_block(C1) ⊕ IV
    /// * Pj = decrypt_block(Cj) ⊕ Cj-1 for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &Vec<u8>`: symmetric encryption key.
    fn aes_decrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = self.sym_nonce.clone().unwrap();
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256)?;
        let ke = &ke_ka[..key.len()].to_vec(); // Encryption Key
        let ka = &ke_ka[key.len()..].to_vec(); // Authentication Key

        let key_schedule = AES::new(ke);

        let msg_copy = self.msg.clone();

        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let block_index = i * 16;
                let xor_block = if block_index >= 16 {
                    &msg_copy[block_index - 16..block_index]
                } else {
                    &iv // Use IV for the first block
                };
                // Decrypt the block in-place without using the output
                AES::decrypt_block(block, 0, &key_schedule.round_key);
                // XOR the decrypted block with the previous ciphertext block
                xor_blocks(block, xor_block);
            });

        remove_pcks7_padding(&mut self.msg);

        let ver = kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256)?;
        self.op_result = match self.digest.as_mut() {
            Ok(digest) if ver == *digest => Ok(()),
            Ok(_) => Err(OperationError::OperationResultNotSet),
            Err(_) => Err(OperationError::SignatureVerificationFailure),
        };
        Ok(())
    }

    /// # Symmetric Encryption using AES in CTR Mode
    /// Encrypts a [`Message`] using the AES algorithm in CTR (Counter) mode.
    /// For more information, refer to NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of encryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// * `Message.sym_nonce` with the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Random(12)
    /// * CTR ← u32 counter starting at 0
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * C1 = P1 ⊕ encrypt_block(IV || CTR1)
    /// * Cj = Pj ⊕ encrypt_block(IV || CTRj) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &[u8]`: symmetric encryption key.
    fn aes_encrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = get_random_bytes(12);
        let counter = 0u32;
        let counter_bytes = counter.to_be_bytes();

        let mut ke_ka = iv.clone();
        ke_ka.extend_from_slice(&counter_bytes);
        ke_ka.extend_from_slice(key);
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256)?;

        let (ke, ka) = ke_ka.split_at(key.len());

        self.sym_nonce = Some(iv.clone());
        self.digest = Ok(kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256)?);

        let key_schedule = AES::new(ke);

        // Parallelize encryption for each block
        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let mut temp = iv.clone();
                let counter = i as u32;
                temp.extend_from_slice(&counter.to_be_bytes());

                AES::encrypt_block(&mut temp, 0, &key_schedule.round_key);

                xor_blocks(block, &temp);
            });

        Ok(())
    }
    /// # Symmetric Decryption using AES in CTR Mode
    /// Decrypts a [`Message`] using the AES algorithm in CTR (Counter) mode.
    /// For more information, refer to NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of decryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Message.sym_nonce
    /// * CTR ← u32 counter starting at 0
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * P1 = C1 ⊕ encrypt_block(IV || CTR1)
    /// * Pj = Cj ⊕ encrypt_block(IV || CTRj) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &[u8]`: symmetric encryption key.
    fn aes_decrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = self
            .sym_nonce
            .clone()
            .ok_or(OperationError::SymNonceNotSet)?;
        let counter = 0u32;
        let counter_bytes = counter.to_be_bytes();

        let mut ke_ka = iv.clone();
        ke_ka.extend_from_slice(&counter_bytes);
        ke_ka.extend_from_slice(key);
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256)?;

        let (ke, ka) = ke_ka.split_at(key.len());

        let key_schedule = AES::new(ke);

        // Parallelize decryption for each block
        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let mut temp = iv.clone();
                let counter = i as u32;
                temp.extend_from_slice(&counter.to_be_bytes());

                AES::encrypt_block(&mut temp, 0, &key_schedule.round_key);

                xor_blocks(block, &temp);
            });

        let ver = kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256)?;
        self.op_result = if let Ok(digest) = self.digest.as_ref() {
            if digest == &ver {
                Ok(())
            } else {
                Err(OperationError::AESCTRDecryptionFailure)
            }
        } else {
            Err(OperationError::DigestNotSet)
        };
        Ok(())
    }
}
