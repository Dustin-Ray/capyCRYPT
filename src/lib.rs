use num_bigint::{BigInt};

#[derive(Debug)]
pub struct E521 {
    pub x: BigInt,
    pub y: BigInt,
    pub p: BigInt,
    pub d: BigInt,
    pub r: BigInt,
    pub n: BigInt,
}


pub struct SymmetricCryptogram {
    pub z: Vec<u8>,
    pub c: Vec<u8>,
    pub t: Vec<u8>
}

pub struct ECCryptogram {
    pub z_x: BigInt,    // Z_x is the x coordinate of the public nonce
    pub z_y: BigInt,    // Z_y is the y coordinate of the public nonce
    pub c: Vec<u8>,     // c represents the ciphertext of an encryption
    pub t: Vec<u8>      // t is the authentication tag for the message
}

pub struct KeyObj {

    id: String,             //Represents the unique ID of the key
    owner: String,          //Represents the owner of the key, can be arbitrary
    KeyType: String,     /*Acceptable values are PUBLIC or PRIVATE.
	PUBLIC keys are used only for encryptions, while PRIVATE keys can
	encrypt or decrypt.
	*/
    pub_key_x: String,        //big.Int value representing E521 X coordinate
    pub_key_y: String,        //big.Int value representing E521 X coordinate
    priv_key: String,        //big.Int value representing secret scalar, nil if KeyType is PUBLIC
    date_created: String,    //Date key was generated
    signature: String,      //Nil unless PUBLIC. Signs 128 bit SHA3 hash of this KeyObj

}


//module for curve and e521 functionality
pub mod curve{
    pub mod e521;
}

// module for sha3 primitives
pub mod sha3{
    pub mod keccakf;
    pub mod sponge;
    pub mod aux_functions;
}

//module for model functions
pub mod model;

//module for gui-related functions
pub mod view{
    pub mod window;
}
