use super::{
    constants::BitLength,
    shake_functions::{kmac_xof, shake},
};
use crate::{Message, SecParam};

pub trait SpongeHashable {
    fn compute_sha3_hash(&mut self, d: SecParam);
    fn compute_tagged_hash(&mut self, pw: &[u8], s: &str, d: SecParam);
}

impl SpongeHashable for Message {
    /// # Message Digest
    /// Computes SHA3-d hash of input. Does not consume input.
    /// Replaces `Message.digest` with result of operation.
    /// ## Arguments:
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    fn compute_sha3_hash(&mut self, d: SecParam) {
        self.digest = shake(&mut self.msg, d)
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
    fn compute_tagged_hash(&mut self, pw: &[u8], s: &str, d: SecParam) {
        self.digest = kmac_xof(pw, &self.msg, d.bit_length(), s, d);
    }
}
