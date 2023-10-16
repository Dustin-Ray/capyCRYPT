use curves::EdCurvePoint;
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
}
