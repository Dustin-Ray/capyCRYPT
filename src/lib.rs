use rug::Integer;

/*
    TODO: 
    - refactor z, z_x, z_y into message
    - fix tag authentication failure
    - update usage examples in docs
    - Fix benches
*/ 

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
/// An object containing the necessary fields for symmetric encryptions and decryptions.
pub struct SymmetricCryptogram {
    /// nonce
    pub z: Vec<u8>,
}

#[derive(Debug)]
/// An object containing the necessary fields for asymmetric encryptions and decryptions.
pub struct ECCryptogram {
    /// Z_x is the x coordinate of the public nonce
    pub z_x: Integer,
    /// Z_y is the y coordinate of the public nonce
    pub z_y: Integer,
    /// c represents the ciphertext of an encryption
    pub t: Vec<u8>,
}

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
    /// Curve Point X coordinate
    pub pub_x: Integer,
    /// Curve Point Y coordinate
    pub pub_y: Integer,
    /// value representing secret scalar, None if KeyType is PUBLIC
    pub priv_key: Vec<u8>,
    /// Date key was generated
    pub date_created: String,
}
