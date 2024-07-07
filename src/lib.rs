#![warn(clippy::just_underscores_and_digits)]
use ecc::signable::Signature;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read};
use tiny_ed448_goldilocks::curve::extended_edwards::ExtendedPoint;

/// A simple error type
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum OperationError {
    UnsupportedSecurityParameter,
    CShakeError,
    KmacError,
    SignatureVerificationFailure,
    SHA3DecryptionFailure,
    KeyDecryptionError,
    EmptyDecryptionError,
    DigestNotSet,
    SymNonceNotSet,
    SecurityParameterNotSet,
    XORFailure,
    BytesToScalarError,
    OperationResultNotSet,
    SignatureNotSet,
    UnsupportedCapacity,
    AESCTRDecryptionFailure,
    SecretNotSet,
    InvalidSecretLength,
    DecapsulationFailure,
    KEMError,
}

/// Module for SHA-3 primitives
pub mod sha3 {
    /// Submodule that implements NIST 800-185 compliant functions
    pub mod aux_functions;
    pub mod constants;
    pub mod encryptable;
    pub mod hashable;
    /// Submodule that implements the Keccak-f[1600] permutation
    pub mod keccakf;
    pub mod shake_functions;
    /// Submodule that implements the sponge construction
    pub mod sponge;
}

pub mod aes {
    pub mod aes_constants;
    pub mod aes_functions;
    pub mod encryptable;
}

pub mod ecc {
    pub mod encryptable;
    pub mod keypair;
    pub mod signable;
}

pub mod kem {
    pub mod encryptable;
    pub mod keypair;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Message struct for which cryptographic traits are defined.
pub struct Message {
    /// Input message
    pub msg: Box<Vec<u8>>,
    /// The digest lengths in FIPS-approved hash functions
    pub d: Option<SecParam>,
    /// Nonce used in symmetric encryption
    pub sym_nonce: Option<Vec<u8>>,
    /// Nonce used in asymmetric encryption
    pub asym_nonce: Option<ExtendedPoint>,
    /// Hash value (also known as message digest)
    pub digest: Vec<u8>,
    /// Schnorr signatures on the input message
    pub sig: Option<Signature>,
    /// ML-KEM encrypted secret as a byte array
    pub kem_ciphertext: Option<Vec<u8>>,
}

impl Message {
    /// Returns a new empty Message instance
    pub fn new(data: Vec<u8>) -> Message {
        Message {
            msg: Box::new(data),
            d: None,
            sym_nonce: None,
            asym_nonce: None,
            digest: vec![],
            sig: None,
            kem_ciphertext: Some(vec![]),
        }
    }

    pub fn write_to_file(&self, filename: &str) -> std::io::Result<()> {
        let json_key_pair = serde_json::to_string(self).unwrap();
        std::fs::write(filename, json_key_pair)
    }

    pub fn read_from_file(filename: &str) -> Result<Message, Box<dyn std::error::Error>> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let message: Message = serde_json::from_str(&contents)?;
        Ok(message)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
/// An enum representing standard digest lengths based on FIPS PUB 202
pub enum SecParam {
    /// Digest length of 224 bits, also known as SHA3-224
    D224 = 224,
    /// Digest length of 256 bits, also known as SHA3-256
    D256 = 256,
    /// Digest length of 384 bits, also known as SHA3-384
    D384 = 384,
    /// Digest length of 512 bits, also known as SHA3-512
    D512 = 512,
}

impl SecParam {
    /// Converts an integer input to the corresponding security parameter.
    /// Supports security levels of 224, 256, 384, and 512 bits.
    pub fn try_from(value: usize) -> Result<SecParam, OperationError> {
        match value {
            224 => Ok(SecParam::D224),
            256 => Ok(SecParam::D256),
            384 => Ok(SecParam::D384),
            512 => Ok(SecParam::D512),
            _ => Err(OperationError::UnsupportedSecurityParameter),
        }
    }

    fn bytepad_value(&self) -> u32 {
        match self {
            SecParam::D224 => 172,
            SecParam::D256 => 168,
            SecParam::D384 => 152,
            SecParam::D512 => 136,
        }
    }
}

pub trait BitLength {
    fn bit_length(&self) -> u64;
}

impl BitLength for SecParam {
    fn bit_length(&self) -> u64 {
        *self as u64
    }
}
