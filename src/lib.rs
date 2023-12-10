#![warn(clippy::just_underscores_and_digits)]
use curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

/// Module for all EC operations.
pub mod curve {
    pub mod affine;
    pub mod extended_edwards;
    pub mod projective_niels;
    pub mod twisted_edwards;
    pub mod field {
        pub mod field_element;
        pub mod lookup_table;
        pub mod scalar;
    }
}

/// Module for sha3 primitives.
pub mod sha3 {
    pub mod aux_functions;
    pub mod keccakf;
    pub mod sponge;
}

pub mod aes {
    pub mod aes_constants;
    pub mod aes_functions;
}

/// Module for encrypt, decrypt, and sign functions.
pub mod ops;

#[derive(Debug)]
/// An object containing the necessary fields for Schnorr signatures.
pub struct Signature {
    /// keyed hash of signed message
    pub h: Vec<u8>,
    /// public nonce
    pub z: Scalar,
}

impl Clone for Signature {
    fn clone(&self) -> Signature {
        Signature {
            h: self.h.clone(),
            z: self.z,
        }
    }
}

#[derive(Debug)]
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

impl Message {
    pub fn new(data: Vec<u8>) -> Message {
        Message {
            msg: Box::new(data),
            d: None,
            sym_nonce: None,
            asym_nonce: None,
            digest: None,
            op_result: None,
            sig: None,
        }
    }
}

#[derive(Debug)]
/// Message type for which cryptographic traits are defined.
pub struct Message {
    pub msg: Box<Vec<u8>>,
    pub d: Option<u64>,
    pub sym_nonce: Option<Vec<u8>>,
    pub asym_nonce: Option<ExtendedPoint>,
    pub digest: Option<Vec<u8>>,
    pub op_result: Option<bool>,
    pub sig: Option<Signature>,
}

pub trait AesEncryptable {
    fn aes_encrypt_cbc(&mut self, key: &[u8]);
    fn aes_decrypt_cbc(&mut self, key: &[u8]);
}

pub trait Hashable {
    fn compute_hash_sha3(&mut self, d: u64);
    fn compute_tagged_hash(&mut self, pw: &mut Vec<u8>, s: &str, d: u64);
}

pub trait PwEncryptable {
    fn pw_encrypt_sha3(&mut self, pw: &[u8], d: u64);
    fn pw_decrypt_sha3(&mut self, pw: &[u8]);
}

pub trait KeyEncryptable {
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: u64);
    fn key_decrypt(&mut self, pw: &[u8]);
}

pub trait Signable {
    fn sign(&mut self, key: &KeyPair, d: u64);
    fn verify(&mut self, pub_key: &ExtendedPoint);
}
