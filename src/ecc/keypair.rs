#![warn(clippy::just_underscores_and_digits)]
use serde::{Deserialize, Serialize};
use sha3::{
    aux_functions::byte_utils::{bytes_to_scalar, get_date_and_time_as_string},
    shake_functions::kmac_xof,
};
use std::fs::File;
use std::io::Read;
use tiny_ed448_goldilocks::curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

use crate::{sha3, OperationError, SecParam};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

impl KeyPair {
    /// # Asymmetric [`KeyPair`] Generation
    /// Generates a (Schnorr/ECDHIES) key pair from passphrase pw.
    ///
    /// ## Algorithm:
    /// * s ← kmac_xof(pw, “”, 448, “K”); s ← 4s
    /// * 𝑉 ← s*𝑮
    /// * key pair: (s, 𝑉)
    /// ## Arguments:
    /// * pw: &Vec<u8> : password as bytes, can be blank but shouldnt be
    /// * owner: String : A label to indicate the owner of the key
    /// * curve: [`EdCurves`] : The selected Edwards curve
    /// ## Returns:
    /// * return  -> [`KeyPair`]: Key object containing owner, private key, public key x and y coordinates, and timestamp.
    /// verification key 𝑉 is hashed together with the message 𝑚
    /// and the nonce 𝑈: hash (𝑚, 𝑈, 𝑉) .
    #[allow(non_snake_case)]
    pub fn new(pw: &[u8], owner: String, d: &SecParam) -> Result<KeyPair, OperationError> {
        let data = kmac_xof(pw, &[], 448, "SK", d)?;
        let s: Scalar = bytes_to_scalar(data).mul_mod(&Scalar::from(4_u64));
        let V = ExtendedPoint::generator() * s;
        Ok(KeyPair {
            owner,
            pub_key: V,
            priv_key: pw.to_vec(),
            date_created: get_date_and_time_as_string(),
        })
    }

    /// # KeyPair Saving
    ///
    /// Saves the key pair to a JSON file.
    ///
    /// ## Usage:
    ///
    /// ```rust
    /// use capycrypt::ecc::ecc_keypair::KeyPair;
    /// use capycrypt::SecParam;
    ///
    /// let key_pair = KeyPair::new("password".as_bytes(), "owner".to_string(), &SecParam::D512)
    ///     .expect("Failed to create key pair");
    ///
    /// // key_pair.write_to_file("keypai1r.json").expect("Failed to save key pair");
    pub fn write_to_file(&self, filename: &str) -> std::io::Result<()> {
        let json_key_pair = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(filename, json_key_pair)
    }

    /// # KeyPair Loading
    ///
    /// Reads a JSON file and creates a `KeyPair` from its contents.
    ///
    /// ## Errors:
    ///
    /// Returns an error if:
    /// - The file cannot be opened or read.
    /// - The JSON content cannot be parsed into a `KeyPair`.
    ///
    /// ## Usage:
    ///
    /// ```rust
    /// use capycrypt::ecc::ecc_keypair::KeyPair;
    ///
    /// // Assuming "keypair.json" contains a serialized KeyPair
    /// match KeyPair::read_from_file("keypair.json") {
    ///     Ok(key_pair) => {
    ///         println!("Loaded KeyPair: {:?}", key_pair);
    ///     },
    ///     Err(err) => eprintln!("Error loading KeyPair: {}", err),
    /// }
    /// ```
    pub fn read_from_file(filename: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let keypair: KeyPair = serde_json::from_str(&contents)?;
        Ok(keypair)
    }
}
