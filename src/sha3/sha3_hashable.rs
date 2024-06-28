use crate::{BitLength, Hashable, Message, OperationError, SecParam};

use super::shake_functions::{kmac_xof, shake};

impl Hashable for Message {
    /// # Message Digest
    /// Computes SHA3-d hash of input. Does not consume input.
    /// Replaces `Message.digest` with result of operation.
    /// ## Arguments:
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// use capycrypt::{Hashable, Message, SecParam};
    /// // Hash the empty string
    /// let mut data = Message::new(vec![]);
    /// // Obtained from echo -n "" | openssl dgst -sha3-256
    /// let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    /// // Compute a SHA3 digest with 128 bits of security
    /// data.compute_hash_sha3(&SecParam::D256);
    /// // Verify successful operation
    /// data.op_result.expect("Hashing a message encountered an error");
    /// ```
    fn compute_hash_sha3(&mut self, d: &SecParam) -> Result<(), OperationError> {
        self.digest = shake(&mut self.msg, d);
        Ok(())
    }

    /// # Tagged Hash
    /// Computes an authentication tag `t` of a byte array `m` under passphrase `pw`.
    /// ## Replaces:
    /// * `Message.t` with keyed hash of plaintext.
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>`: symmetric encryption key, can be blank but shouldnt be
    /// * `message: &mut Vec<u8>`: message to encrypt
    /// * `s: &mut str`: domain seperation string
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// use capycrypt::{Hashable, Message, SecParam::{D512}};
    /// let mut pw = "test".as_bytes().to_vec();
    /// let mut data = Message::new(vec![]);
    /// let expected = "0f9b5dcd47dc08e08a173bbe9a57b1a65784e318cf93cccb7f1f79f186ee1caeff11b12f8ca3a39db82a63f4ca0b65836f5261ee64644ce5a88456d3d30efbed";
    /// data.compute_tagged_hash(&mut pw, &"", &D512);
    /// // Verify successful operation
    /// data.op_result.expect("Computing an Authentication Tag encountered an error");
    /// ```
    fn compute_tagged_hash(&mut self, pw: &[u8], s: &str, d: &SecParam) {
        self.digest = kmac_xof(pw, &self.msg, d.bit_length(), s, d);
    }
}
