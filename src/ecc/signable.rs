use crate::{
    sha3::{
        aux_functions::byte_utils::{bytes_to_scalar, scalar_to_bytes},
        shake_functions::kmac_xof,
    },
    Message, OperationError, SecParam,
};
use serde::{Deserialize, Serialize};
use tiny_ed448_goldilocks::curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

use super::keypair::KeyPair;

pub trait Signable {
    fn sign(&mut self, key: &KeyPair, d: &SecParam) -> Result<(), OperationError>;
    fn verify(&mut self, pub_key: &ExtendedPoint) -> Result<(), OperationError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// An object containing the necessary fields for Schnorr signatures.
pub struct Signature {
    /// keyed hash of signed message
    pub h: Vec<u8>,
    /// public nonce
    pub z: Scalar,
}

impl Signable for Message {
    /// # Schnorr Signatures
    /// Signs a [`Message`] under passphrase pw.
    ///
    /// ## Algorithm:
    /// * `s` ← kmac_xof(pw, “”, 448, “K”); s ← 4s
    /// * `k` ← kmac_xof(s, m, 448, “N”); k ← 4k
    /// * `𝑈` ← k*𝑮;
    /// * `ℎ` ← kmac_xof(𝑈ₓ , m, 448, “T”); 𝑍 ← (𝑘 – ℎ𝑠) mod r
    ///
    /// ## Arguments:
    /// * key: &[`KeyPair`], : reference to KeyPair.
    /// * d: u64: encryption security strength in bits. Can only be 224, 256, 384, or 512.
    ///
    /// ## Assumes:
    /// * Some(key.priv_key)
    #[allow(non_snake_case)]
    fn sign(&mut self, key: &KeyPair, d: &SecParam) -> Result<(), OperationError> {
        let s_bytes = kmac_xof(&key.priv_key, &[], 448, "SK", d);
        let s = bytes_to_scalar(s_bytes).mul_mod(&Scalar::from(4_u64));
        let s_bytes = scalar_to_bytes(&s);

        let k_bytes = kmac_xof(&s_bytes, &self.msg, 448, "N", d);
        let k = bytes_to_scalar(k_bytes) * Scalar::from(4_u64);

        let U = ExtendedPoint::generator() * k;
        let ux_bytes = U.to_affine().x.to_bytes();

        let h = kmac_xof(&ux_bytes, &self.msg, 448, "T", d);
        let h_big = bytes_to_scalar(h.clone());

        let z = k - h_big.mul_mod(&s);
        self.sig = Some(Signature { h, z });
        self.d = Some(*d);
        Ok(())
    }

    /// # Signature Verification
    /// Verifies a [`Signature`] (h, 𝑍) for a byte array m under the (Schnorr/
    /// ECDHIES) public key 𝑉.
    /// ## Algorithm:
    /// * 𝑈 ← 𝑍*𝑮 + h𝑉
    /// ## Arguments:
    /// * sig: &[`Signature`]: Pointer to a signature object (h, 𝑍)
    /// * pubKey: CurvePoint key 𝑉 used to sign message m
    /// * message: Vec<u8> of message to verify
    /// ## Assumes:
    /// * Some(key.pub_key)
    /// * Some([`Message`].sig)
    #[allow(non_snake_case)]
    fn verify(&mut self, pub_key: &ExtendedPoint) -> Result<(), OperationError> {
        let sig = self.sig.as_ref().ok_or(OperationError::SignatureNotSet)?;
        let d = self
            .d
            .as_ref()
            .ok_or(OperationError::SecurityParameterNotSet)?;

        let h_scalar = bytes_to_scalar(sig.h.clone());
        let U = ExtendedPoint::generator() * sig.z + (*pub_key * h_scalar);

        let h_p = kmac_xof(&U.to_affine().x.to_bytes(), &self.msg, 448, "T", d);

        self.op_result = if h_p == sig.h {
            Ok(())
        } else {
            Err(OperationError::SignatureVerificationFailure)
        };
        Ok(())
    }
}
