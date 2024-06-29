use crate::{
    sha3::{
        aux_functions::byte_utils::{bytes_to_scalar, get_random_bytes, xor_bytes},
        shake_functions::kmac_xof,
    },
    Message, OperationError, SecParam,
};
use tiny_ed448_goldilocks::curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

pub trait KeyEncryptable {
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: &SecParam) -> Result<(), OperationError>;
    fn key_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError>;
}

impl KeyEncryptable for Message {
    /// # Asymmetric Encryption
    /// Encrypts a [`Message`] in place under the (Schnorr/ECDHIES) public key 𝑉.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// exchanged with recipient. SECURITY NOTE: ciphertext length == plaintext length
    /// ## Replaces:
    /// * `Message.data` with result of encryption.
    /// * `Message.t` with keyed hash of plaintext.
    /// * `Message.asym_nonce` with z, as defined below.
    /// ## Algorithm:
    /// * k ← Random(448); k ← 4k
    /// * W ← kV; 𝑍 ← k*𝑮
    /// * (ke || ka) ← kmac_xof(W x , “”, 448 * 2, “P”)
    /// * c ← kmac_xof(ke, “”, |m|, “PKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 448, “PKA”)
    /// ## Arguments:
    /// * pub_key: [`EdCurvePoint`] : X coordinate of public key 𝑉
    /// * d: u64: Requested security strength in bits. Can only be 224, 256, 384, or 512.
    #[allow(non_snake_case)]
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: &SecParam) -> Result<(), OperationError> {
        self.d = Some(*d);
        let k = bytes_to_scalar(get_random_bytes(56)).mul_mod(&Scalar::from(4_u64));
        let w = (*pub_key * k).to_affine();
        let Z = (ExtendedPoint::generator() * k).to_affine();

        let ke_ka = kmac_xof(&w.x.to_bytes(), &[], 448 * 2, "PK", d);
        let (ke, ka) = ke_ka.split_at(ke_ka.len() / 2);

        let t = kmac_xof(ka, &self.msg, 448, "PKA", d);

        let msg_len = self.msg.len();
        xor_bytes(&mut self.msg, &kmac_xof(ke, &[], msg_len * 8, "PKE", d));

        self.digest = t;
        self.asym_nonce = Some(Z.to_extended());
        Ok(())
    }

    /// # Asymmetric Decryption
    /// Decrypts a [`Message`] in place under private key.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// derived from 𝑍.
    ///
    /// ## Assumes:
    /// * well-formed encryption
    /// * Some(Message.t)
    /// * Some(Message.z)
    ///
    /// ## Replaces:
    /// * `Message.data` with result of decryption.
    /// * `Message.op_result` with result of comparision of `Message.t` == keyed hash of decryption.
    ///
    /// ## Algorithm:
    /// * s ← KMACXOF256(pw, “”, 448, “K”); s ← 4s
    /// * W ← sZ
    /// * (ke || ka) ← KMACXOF256(W x , “”, 448 * 2, “P”)
    /// * m ← KMACXOF256(ke, “”, |c|, “PKE”) ⊕ c
    /// * t’ ← KMACXOF256(ka, m, 448, “PKA”)
    ///
    /// ## Arguments:
    /// * pw: &[u8]: password used to generate ```CurvePoint``` encryption key.
    /// * d: u64: encryption security strength in bits. Can only be 224, 256, 384, or 512.
    #[allow(non_snake_case)]
    fn key_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError> {
        let Z = self.asym_nonce.ok_or(OperationError::SymNonceNotSet)?;
        let d = self
            .d
            .as_ref()
            .ok_or(OperationError::SecurityParameterNotSet)?;

        let s_bytes = kmac_xof(pw, &[], 448, "SK", d);
        let s = bytes_to_scalar(s_bytes).mul_mod(&Scalar::from(4_u64));
        let Z = (Z * s).to_affine();

        let ke_ka = kmac_xof(&Z.x.to_bytes(), &[], 448 * 2, "PK", d);
        let (ke, ka) = ke_ka.split_at(ke_ka.len() / 2);

        let xor_result = kmac_xof(ke, &[], self.msg.len() * 8, "PKE", d);
        xor_bytes(&mut self.msg, &xor_result);

        let t_p = kmac_xof(ka, &self.msg, 448, "PKA", d);

        self.op_result = if self.digest == t_p {
            Ok(())
        } else {
            // revert back to the encrypted message
            xor_bytes(&mut self.msg, &xor_result);

            Err(OperationError::KeyDecryptionError)
        };

        Ok(())
    }
}
