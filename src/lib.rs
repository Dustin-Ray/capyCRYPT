use rug::Integer;

///module for curve and e521 functionality
pub mod curve;
/// module for sha3 primitives
pub mod sha3 {
    pub mod aux_functions;
    pub mod keccakf;
    pub mod sponge;
}

/// module for model functions
pub mod model;

#[derive(Debug)]
pub struct SymmetricCryptogram {
    pub z: Vec<u8>, // nonce
    pub c: Vec<u8>, // ciphertext
    pub t: Vec<u8>, // authentication tag
}

#[derive(Debug)]
pub struct ECCryptogram {
    pub z_x: Integer, // Z_x is the x coordinate of the public nonce
    pub z_y: Integer, // Z_y is the y coordinate of the public nonce
    pub c: Vec<u8>,   // c represents the ciphertext of an encryption
    pub t: Vec<u8>,   // t is the authentication tag for the message
}

#[derive(Debug)]
pub struct Signature {
    h: Vec<u8>, // keyed hash of signed message
    z: Integer, // public nonce
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
pub struct KeyObj {
    pub owner: String,        // Represents the owner of the key, can be arbitrary
    pub pub_x: Integer,       // E521 X coordinate
    pub pub_y: Integer,       // E521 Y coordinate
    pub priv_key: Vec<u8>,    // value representing secret scalar, nil if KeyType is PUBLIC
    pub date_created: String, // Date key was generated
}
