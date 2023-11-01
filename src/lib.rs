use curves::{EdCurvePoint, EdCurves};
use rug::Integer;

/// Module for all EC operations.
pub mod curves;
/// Module for sha3 primitives.
pub mod sha3 {
    pub mod aux_functions;
    pub mod keccakf;
    pub mod sponge;
}

/// Module for encrypt, decrypt, and sign functions.
pub mod ops;

#[derive(Debug)]
/// An object containing the necessary fields for Schnorr signatures.
pub struct Signature {
    /// keyed hash of signed message
    pub h: Vec<u8>,
    /// public nonce
    pub z: Integer,
}

impl Clone for Signature {
    fn clone(&self) -> Signature {
        Signature {
            h: self.h.clone(),
            z: self.z.clone(),
        }
    }
}

#[derive(Debug)]
/// An object containing the fields necessary to represent an asymmetric keypair.
pub struct KeyPair {
    /// String indicating the owner of the key, can be arbitrary
    pub owner: String,
    /// Public encryption key
    pub pub_key: EdCurvePoint,
    /// value representing secret scalar, None if KeyType is PUBLIC
    pub priv_key: Vec<u8>,
    /// Date key was generated
    pub date_created: String,
    /// Selected curve type
    pub curve: EdCurves,
}

impl Message {
    pub fn new(data: Vec<u8>) -> Message {
        Message {
            msg: Box::new(data),
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
    pub sym_nonce: Option<Vec<u8>>,
    pub asym_nonce: Option<EdCurvePoint>,
    pub digest: Option<Vec<u8>>,
    pub op_result: Option<bool>,
    pub sig: Option<Signature>,
}

pub trait Hashable {
    fn compute_sha3_hash(&mut self, d: u64);
    fn compute_tagged_hash(&mut self, pw: &mut Vec<u8>, s: &str, d: u64);
}

pub trait PwEncryptable {
    fn pw_encrypt(&mut self, pw: &[u8], d: u64);
    fn pw_decrypt(&mut self, pw: &[u8], d: u64);
}

pub trait KeyEncryptable {
    fn key_encrypt(&mut self, pub_key: &EdCurvePoint, d: u64);
    fn key_decrypt(&mut self, pw: &[u8], d: u64);
}

pub trait Signable {
    fn sign(&mut self, key: &KeyPair, d: u64);
    fn verify(&mut self, pub_key: &EdCurvePoint, d: u64);
}
