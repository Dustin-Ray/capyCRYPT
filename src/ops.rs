use crate::sha3::{
    aux_functions::{
        byte_utils::{
            big_to_bytes, bytes_to_big, get_date_and_time_as_string, get_random_bytes, xor_bytes,
        },
        nist_800_185::{byte_pad, encode_string, right_encode},
    },
    sponge::{sponge_absorb, sponge_squeeze},
};
use crate::{
    curves::{
        order, EdCurvePoint,
        EdCurves::{self, E448},
        Generator,
    },
    Hashable, KeyEncryptable, Message, PwEncryptable, Signable,
};
use crate::{KeyPair, Signature};

use rug::Integer;
use std::borrow::{Borrow, BorrowMut};

const SELECTED_CURVE: EdCurves = E448;

/// # SHA3-Keccak
/// ref NIST FIPS 202.
/// ## Arguments:
/// * `n: &mut Vec<u8>`: pointer to message to be hashed.
/// * `d: usize`: requested output length and security strength
/// ## Returns:
/// * `return  -> Vec<u8>`: SHA3-d message digest
fn shake(n: &mut Vec<u8>, d: u64) -> Vec<u8> {
    let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
    if bytes_to_pad == 1 {
        //delim suffix
        n.extend_from_slice(&[0x86]);
    } else {
        //delim suffix
        n.extend_from_slice(&[0x06]);
    }
    sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600 - (2 * d))
}

/// # Customizable SHAKE
/// Implements FIPS 202 Section 3. Returns: customizable and
/// domain-seperated length `L` SHA3XOF hash of input string.
/// ## Arguments:
/// * `x: &mut Vec<u8>`: input message as ```Vec<u8>```
/// * `l: u64`: requested output length
/// * `n: &str`: optional function name string
/// * `s: &str`: option customization string
/// ## Returns:
/// * `return -> Vec<u8>`: SHA3XOF hash of length `l` of input message `x`
pub fn cshake(x: &mut Vec<u8>, l: u64, n: &str, s: &str, d: u64) -> Vec<u8> {
    if n.is_empty() && s.is_empty() {
        shake(x, l);
    }
    let mut encoded_n = encode_string(&mut n.as_bytes().to_vec());
    let encoded_s = encode_string(&mut s.as_bytes().to_vec());

    encoded_n.extend_from_slice(&encoded_s);

    let bytepad_w = match d {
        256 => 168,
        512 => 136,
        _ => panic!("Value must be either 256 or 512"),
    };

    let mut out = byte_pad(&mut encoded_n, bytepad_w);

    out.append(x);
    out.push(0x04);
    sponge_squeeze(&mut sponge_absorb(&mut out, d), l, 1600 - d)
}

/// # Keyed Message Authtentication
/// Generates keyed hash for given input as specified in NIST SP 800-185 section 4.
/// ## Arguments:
/// * `k: &mut Vec<u8>`: key. SP 800 185 8.4.1 KMAC Key Length requires key length >= d
/// * `x: &mut Vec<u8>`: byte-oriented message
/// * `l: u64`: requested bit output length
/// * `s: &str`: customization string
/// * `d: u64`: the security parameter for the operation. NIST-standard values for d consist of the following:
/// d = 512; 256 bits of security
/// d = 256; 128 bits of security
///
/// ## Returns:
/// * `return  -> Vec<u8>`: kmac_xof of `x` under `k`
/// ## Usage:
/// ```
/// ```
pub fn kmac_xof(k: &mut Vec<u8>, x: &Vec<u8>, l: u64, s: &str, d: u64) -> Vec<u8> {
    let mut encode_k = encode_string(k);
    let bytepad_w = match d {
        256 => 168,
        512 => 136,
        _ => panic!("Value must be either 256 or 512"),
    };
    let mut bp = byte_pad(&mut encode_k, bytepad_w);
    bp.append(&mut x.to_owned());
    let mut right_enc = right_encode(0); // SP 800-185 4.3.1 KMAC with Arbitrary-Length Output
    bp.append(&mut right_enc);
    cshake(&mut bp, l, "KMAC", s, d)
}

impl Hashable for Message {
    /// # Message Digest
    /// Computes SHA3-d hash of input
    /// ## Arguments:
    /// * `data: &mut Vec<u8>`: representing any data requested to be hashed
    /// ## Returns:
    /// * `return  -> Vec<u8>`: containing result of shake operation of size 512 bits
    /// ## Usage:
    /// ```
    /// ```
    fn compute_sha3_hash(&mut self, d: u64) {
        self.digest = match d {
            224 | 256 | 384 | 512 => Some(shake(&mut self.msg, d)),
            _ => panic!("Value must be either 224, 256. 384, or 512"),
        }
    }

    /// # Tagged Hash
    /// Computes an authentication tag `t` of a byte array `m` under passphrase `pw`
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>`: symmetric encryption key, can be blank but shouldnt be
    /// * `message: &mut Vec<u8>`: message to encrypt
    /// * `s: &mut str`: customization string
    /// * `d: u64`: requested security strength
    /// ## Returns:
    /// * `return  -> Vec<u8>`: `t` ← kmac_xof(pw, m, 512, “T”) as ```Vec<u8>``` of size `l`
    /// ## Usage:
    /// ```
    /// ```
    fn compute_tagged_hash(&mut self, pw: &mut Vec<u8>, s: &str, d: u64) {
        self.digest = match d {
            224 | 256 | 384 | 512 => Some(kmac_xof(pw, &self.msg, d, s, d)),
            _ => panic!("Value must be either 224, 256. 384, or 512"),
        }
    }
}

impl PwEncryptable for Message {
    /// # Symmetric Encryption
    /// Encrypts a byte array m symmetrically under passphrase pw:
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * z ← Random(512)
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * c ← kmac_xof(ke, “”, |m|, “SKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>`: symmetric encryption key, can be blank but shouldnt be
    /// * `msg: &mut Box<Vec<u8>>`: borrowed pointer to message to encrypt
    /// ## Returns:
    /// * `return -> SymmetricCryptogram`: SymmetricCryptogram(z, c, t)
    ///
    /// ## Usage:
    /// ```
    /// ```
    fn pw_encrypt(&mut self, pw: &[u8], d: u64) {
        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.append(&mut pw.to_owned());
        let ke_ka = kmac_xof(&mut ke_ka, &vec![], 1024, "S", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        self.digest = Some(kmac_xof(ka, &self.msg, 512, "SKA", d));
        let c = kmac_xof(ke, &vec![], (self.msg.len() * 8) as u64, "SKE", d);
        xor_bytes(self.msg.borrow_mut(), &c);
        self.sym_nonce = Some(z);
    }

    /// # Symmetric Decryption
    /// Decrypts a symmetric cryptogram (z, c, t) under passphrase pw.
    /// Assumes that decryption is well-formed.
    /// ## Algorithm:
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * m ← kmac_xof(ke, “”, |c|, “SKE”) ⊕ c
    /// * t’ ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `msg: &mut Box<SymmetricCryptogram>`: borrowed pointer to cryptogram to decrypt as `SymmetricCryptogram`, assumes valid format
    /// * `pw: &mut Vec<u8>`: decryption password, can be blank
    /// ## Returns:
    /// * `return -> bool`: t` == t, result of tag verification
    /// ## Usage:
    /// ```
    ///
    /// ```
    fn pw_decrypt(&mut self, pw: &[u8], d: u64) {
        let mut z_pw = self.sym_nonce.clone().unwrap();
        z_pw.append(&mut pw.to_owned());
        let ke_ka = kmac_xof(&mut z_pw, &vec![], 1024, "S", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let m = kmac_xof(ke, &vec![], (self.msg.len() * 8) as u64, "SKE", d);
        xor_bytes(&mut self.msg, &m);
        let new_t = &kmac_xof(ka, &self.msg, 512, "SKA", d);
        self.op_result = Some(self.digest.as_mut().unwrap() == new_t);
    }
}

impl KeyPair {
    /// # Asymmetric Keypair Generation
    /// Generates a (Schnorr/ECDHIES) key pair from passphrase pw:
    /// ## Algorithm:
    /// * s ← kmac_xof(pw, “”, 512, “K”); s ← 4s
    /// * 𝑉 ← s*𝑮
    /// * key pair: (s, 𝑉)
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>` : password as bytes, can be blank but shouldnt be
    /// * `owner: String` : A label to indicate the owner of the key
    /// ## Returns:
    /// * `return  -> KeyObj`: Key object containing owner, private key, public key x and y coordinates, and timestamp.
    /// verification key 𝑉 is hashed together with the message 𝑚
    /// and the nonce 𝑈: hash (𝑚, 𝑈, 𝑉) .
    /// ## Usage:
    /// ```  
    /// ```
    pub fn new(pw: &Vec<u8>, owner: String, curve: EdCurves, d: u64) -> KeyPair {
        let s: Integer = (bytes_to_big(kmac_xof(&mut pw.to_owned(), &vec![], 512, "K", d)) * 4)
            % order(SELECTED_CURVE);
        let pub_key = EdCurvePoint::generator(SELECTED_CURVE, false) * (s);
        KeyPair {
            owner,
            pub_key,
            priv_key: pw.to_vec(),
            date_created: get_date_and_time_as_string(),
            curve
        }
    }
}

impl KeyEncryptable for Message {
    /// # Asymmetric Encryption
    /// Encrypts a byte array m under the (Schnorr/ECDHIES) public key 𝑉.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// exchanged with recipient. SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * k ← Random(512); k ← 4k
    /// * W ← kV; 𝑍 ← k*𝑮
    /// * (ke || ka) ← kmac_xof(W x , “”, 1024, “P”)
    /// * c ← kmac_xof(ke, “”, |m|, “PKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 512, “PKA”)
    /// ## Arguments:
    /// * `pub_key: CurvePoint` : X coordinate of public static key 𝑉, accepted as ```CurvePoint```
    /// * `message: &mut Box<Vec<u8>>`: borrowed pointer to message of any length
    /// ## Returns:
    /// * `return -> ECCryptogram` : cryptogram: (𝑍, c, t) = 𝑍||c||t
    /// ## Usage:
    /// ```
    /// ```
    fn key_encrypt(&mut self, pub_key: &EdCurvePoint, d: u64) {
        let k: Integer = (bytes_to_big(get_random_bytes(64)) * 4) % order(SELECTED_CURVE);
        let w = pub_key.clone() * k.clone();
        let z = EdCurvePoint::generator(SELECTED_CURVE, false) * k;

        let ke_ka = kmac_xof(&mut big_to_bytes(w.x), &vec![], 1024, "PK", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();

        let t = kmac_xof(ka, self.msg.borrow(), 512, "PKA", d);
        let c = kmac_xof(ke, &vec![], (self.msg.len() * 8) as u64, "PKE", d);
        xor_bytes(&mut self.msg, &c);

        self.digest = Some(t);
        self.asym_nonce = Some(z);
    }

    /// # Asymmetric Decryption
    /// Decrypts a cryptogram in place under password. Assumes cryptogram is well-formed.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// derived from 𝑍.
    /// ## Algorithm:
    /// * s ← KMACXOF256(pw, “”, 512, “K”); s ← 4s
    /// * W ← sZ
    /// * (ke || ka) ← KMACXOF256(W x , “”, 1024, “P”)
    /// * m ← KMACXOF256(ke, “”, |c|, “PKE”) ⊕ c
    /// * t’ ← KMACXOF256(ka, m, 512, “PKA”)
    /// ## Arguments:
    /// * `pw: &mut [u8]`: password used to generate ```CurvePoint``` encryption key.
    /// * `message: &mut ECCryptogram`: cryptogram of format ```(𝑍||c||t)```
    /// ## Returns:
    /// * `return  -> bool`: Decryption of cryptogram ```𝑍||c||t iff t` = t```
    /// ## Usage:
    /// ```
    /// ```
    fn key_decrypt(&mut self, pw: &[u8], d: u64) {
        let z = self.asym_nonce.clone().unwrap();
        let s: Integer =
            (bytes_to_big(kmac_xof(&mut pw.to_owned(), &vec![], 512, "K", d)) * 4) % z.clone().n;
        let w = z * s;

        let ke_ka = kmac_xof(&mut big_to_bytes(w.x), &vec![], 1024, "PK", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();

        let m = Box::new(kmac_xof(ke, &vec![], (self.msg.len() * 8) as u64, "PKE", d));
        xor_bytes(&mut self.msg, &m);
        let t_p = kmac_xof(&mut ka.clone(), &self.msg, 512, "PKA", d);
        self.op_result = Some(t_p == self.digest.clone().unwrap());
    }
}

impl Signable for Message {
    /// # Schnorr Signatures
    /// Generates a signature for a byte array m under passphrase pw.
    /// ## Algorithm:
    /// * `s` ← kmac_xof(pw, “”, 512, “K”); s ← 4s
    /// * `k` ← kmac_xof(s, m, 512, “N”); k ← 4k
    /// * `𝑈` ← k*𝑮;
    /// * `ℎ` ← kmac_xof(𝑈ₓ , m, 512, “T”); 𝑍 ← (𝑘 – ℎ𝑠) mod r
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>, message`: pointer to passphrase of any length
    /// * `message: &mut Box<Vec<u8>>`: borrowed pointer to message of any length
    /// ## Returns:
    /// * `return -> Signature`: signature: (`ℎ`, `𝑍`)
    /// ## Usage
    /// ```
    /// ```
    fn sign(&mut self, pw: &mut Vec<u8>, d: u64) {
        let s: Integer = bytes_to_big(kmac_xof(pw, &vec![], 512, "K", d)) * 4;
        let mut s_bytes = big_to_bytes(s.clone());

        let k: Integer = bytes_to_big(kmac_xof(&mut s_bytes, &self.msg, 512, "N", d)) * 4;

        let u = EdCurvePoint::generator(SELECTED_CURVE, false) * k.clone();
        let mut ux_bytes = big_to_bytes(u.x);
        let h = kmac_xof(&mut ux_bytes, &self.msg, 512, "T", d);
        let h_big = bytes_to_big(h.clone());
        //(a % b + b) % b
        let z = ((k - (h_big * s)) % u.r.clone() + u.r.clone()) % u.r;
        self.sig = Some(Signature { h, z })
    }
    /// # Signature Verification
    /// Verifies a signature (h, 𝑍) for a byte array m under the (Schnorr/
    /// ECDHIES) public key 𝑉:
    /// ## Algorithm:
    /// * 𝑈 ← 𝑍*𝑮 + h𝑉
    /// ## Arguments:
    /// * `sig: &Signature`: Pointer to a signature object (h, 𝑍)
    /// * `pubKey: CurvePoint` key 𝑉 used to sign message m
    /// * `message: Vec<u8>` of message to verify
    /// ## Returns:
    /// * `return`: true if, and only if, kmac_xof(𝑈ₓ , m, 512, “T”) = h
    /// ## Usage
    /// ```
    /// ```
    fn verify(&mut self, pub_key: EdCurvePoint, d: u64) {
        let mut u = EdCurvePoint::generator(SELECTED_CURVE, false) * self.sig.clone().unwrap().z;
        let hv = pub_key * bytes_to_big(self.sig.clone().unwrap().h);
        u = u + &hv;
        let h_p = kmac_xof(&mut big_to_bytes(u.x), &self.msg, 512, "T", d);
        self.op_result = Some(h_p == self.sig.clone().unwrap().h)
    }
}
