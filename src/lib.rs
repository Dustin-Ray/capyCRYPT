#![warn(clippy::just_underscores_and_digits)]
/// Elliptic curve backend
use tiny_ed448_goldilocks::curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

/// Module for SHA-3 primitives
pub mod sha3 {

    /// Submodule that implements NIST 800-185 compliant functions
    pub mod aux_functions;

    /// Submodule that implements the Keccak-f[1600] permutation
    pub mod keccakf;

    /// Submodule that implements the sponge construction
    pub mod sponge;
}

pub mod aes {
    pub mod aes_constants;
    pub mod aes_functions;
}

/// Module for encrypt, decrypt, and sign functions.
pub mod ops;

#[derive(Debug, PartialEq)]
/// A simple error type
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
}

#[derive(Debug, Clone)]
/// An object containing the necessary fields for Schnorr signatures.
pub struct Signature {
    /// keyed hash of signed message
    pub h: Vec<u8>,
    /// public nonce
    pub z: Scalar,
}

#[derive(Debug, Clone)]
/// An object containing the fields necessary to represent an asymmetric keypair.
pub struct KeyPair {
    /// String indicating the owner of the key, can be arbitrary
    pub owner: String,
    /// Public encryption key
    pub pub_key: ExtendedPoint,
    /// value representing secret scalar, None if KeyType is PUBLIC
    pub priv_key: Vec<u8>,
    /// Date key was generated
    pub date_created: String,
}

#[derive(Debug)]
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
    pub digest: Result<Vec<u8>, OperationError>,
    /// Result of the cryptographic trait
    pub op_result: Result<(), OperationError>,
    /// Schnorr signatures on the input message
    pub sig: Option<Signature>,
}

impl Message {
    /// Returns a new Message instance
    pub fn new(data: Vec<u8>) -> Message {
        Message {
            msg: Box::new(data),
            d: None,
            sym_nonce: None,
            asym_nonce: None,
            digest: Ok(vec![]),
            op_result: Ok(()),
            sig: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
    fn bytepad_value(&self) -> u32 {
        match self {
            SecParam::D224 => 172,
            SecParam::D256 => 168,
            SecParam::D384 => 152,
            SecParam::D512 => 136,
        }
    }

    pub fn validate(&self) -> Result<(), OperationError> {
        match self {
            SecParam::D224 | SecParam::D256 | SecParam::D384 | SecParam::D512 => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// An enum representing standard capacity valuess based on FIPS PUB 202.
/// (The capacity of a sponge function) = 2 * (digest length)
pub(crate) enum Capacity {
    /// 2 * SecParam.D224
    C448 = 448,
    /// 2 * SecParam.D256
    C512 = 512,
    /// 2 * SecParam.D384
    C768 = 768,
    /// 2 * SecParam.D512
    C1024 = 1024,
}

impl Capacity {
    /// This function effectively maps a given bit length to the appropriate capacity value enum variant,
    fn from_bit_length(bit_length: u64) -> Self {
        match bit_length * 2 {
            x if x <= 448 => Capacity::C448,
            x if x <= 512 => Capacity::C512,
            x if x <= 768 => Capacity::C768,
            _ => Capacity::C1024,
        }
    }
}

/// OutputLength struct for storing the output length.
pub struct OutputLength {
    value: u64,
}

impl OutputLength {
    const MAX_VALUE: u64 = u64::MAX;

    pub fn try_from(value: u64) -> Result<Self, OperationError> {
        if value < Self::MAX_VALUE {
            Ok(OutputLength { value })
        } else {
            Err(OperationError::UnsupportedSecurityParameter)
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

/// Rate struct for storing the rate value.
/// Rate is the number of input bits processed per invocation of the underlying function in sponge construction.
pub struct Rate {
    value: u64,
}

impl Rate {
    /// Rate = (Permutation width) - (Capacity)
    pub fn from<R: BitLength + ?Sized>(sec_param: &R) -> Self {
        Rate {
            value: (1600 - sec_param.bit_length()),
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

impl BitLength for Capacity {
    fn bit_length(&self) -> u64 {
        *self as u64
    }
}

impl BitLength for SecParam {
    fn bit_length(&self) -> u64 {
        *self as u64
    }
}

impl BitLength for Rate {
    fn bit_length(&self) -> u64 {
        self.value
    }
}

impl BitLength for OutputLength {
    fn bit_length(&self) -> u64 {
        self.value()
    }
}

pub trait AesEncryptable {
    fn aes_encrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_decrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_encrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError>;
    fn aes_decrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError>;
}

pub trait BitLength {
    fn bit_length(&self) -> u64;
}

pub trait Hashable {
    fn compute_hash_sha3(&mut self, d: &SecParam) -> Result<(), OperationError>;
    fn compute_tagged_hash(&mut self, pw: &[u8], s: &str, d: &SecParam);
}

pub trait SpongeEncryptable {
    fn sha3_encrypt(&mut self, pw: &[u8], d: &SecParam) -> Result<(), OperationError>;
    fn sha3_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError>;
}

pub trait KeyEncryptable {
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: &SecParam) -> Result<(), OperationError>;
    fn key_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError>;
}

pub trait Signable {
    fn sign(&mut self, key: &KeyPair, d: &SecParam) -> Result<(), OperationError>;
    fn verify(&mut self, pub_key: &ExtendedPoint) -> Result<(), OperationError>;
}

pub trait UpdateFinalize {
    fn update(&mut self, write_data: &[u8]);
    fn finalize(self, output_length: &u64) -> Result<Box<Vec<u8>>, OperationError>;
}

const RATE_IN_BYTES: usize = 136; // SHA3-256 r = 1088 / 8 = 136

#[cfg(test)]
const NIST_DATA_SPONGE_INIT: [u8; 200] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];
