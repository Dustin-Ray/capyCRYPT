pub mod shake_functions {
    extern crate num_bigint;
    use std::ops::Mul;
    use crate::curve::e521::mod_formula;
    use crate::{SymmetricCryptogram, KeyObj, ECCryptogram, E521};
    use num::BigInt;
    use crate::curve::e521::e521::{set_n, get_e521_gen_point, PointOps};
    use crate::sha3::sponge::sponge_function::{sponge_squeeze, sponge_absorb};
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};
    use crate::sha3::aux_functions::byte_utils::{
        xor_bytes, 
        get_random_bytes, 
        get_date_and_time_as_string, 
        bytes_to_big_int};
    
    /// SHA3-Keccak ref NIST FIPS 202.
    /// * `n`: pointer to message to be hashed.
    /// * `d`: requested output length
    fn shake(n: &mut Vec<u8>, d: usize) -> Vec<u8> {
        let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
        if bytes_to_pad == 1 { n.extend_from_slice(&[0x86]);} //delim suffix
        else { n.extend_from_slice(&[0x06]);} //delim suffix
        return  sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600-(2*d));
    }
 
    /// FIPS 202 Section 3 cSHAKE function returns customizable and
    /// domain seperated length L SHA3XOF hash of input string.
    /// * `x`: input message as ```Vec<u8>```
    /// * `l`: requested output length
    /// * `n`: optional function name string
    /// * `s`: option customization string
    /// * `return`: SHA3XOF hash of length `l` of input message `x`
    pub fn cshake(x: &mut Vec<u8>, l: u64, n: &str, s: &str) -> Vec<u8> {
        if n == "" && s == "" { return shake(x, l as usize) }
        let mut encoded_n = encode_string(&mut n.as_bytes().to_vec());
        let mut encoded_s = encode_string(&mut s.as_bytes().to_vec());
        encoded_n.extend_from_slice(& mut encoded_s);
        let mut out = byte_pad(&mut encoded_n, 136);
        out.append(x);
        out.push(0x04);
        return sponge_squeeze(&mut sponge_absorb(&mut out, 512), l as usize, 1600-512);
    }

    /// Generates keyed hash for given input as specified in NIST SP 800-185 section 4. 
    /// * `k`: key
    /// * `x`: byte-oriented message
    /// * `l`: requested bit length
    /// * `s`: customization string
    /// * `return`: kmac_xof_256 of `x` under `k`
    pub fn kmac_xof_256<'a>(k: &mut Vec<u8>, x: &'a mut Vec<u8>, l: u64, s: &str) -> Vec<u8>{
        let mut encode_s = encode_string(k);
        let mut bp = byte_pad(&mut encode_s, 136);
        bp.append(x); //x is dropped here? 
        let mut right_enc = right_encode(0);
        bp.append(&mut right_enc);
        let res = cshake(&mut bp, l, "KMAC", s);
        res
    }

    /// Computes SHA3-512 hash of data
    /// * `data`: ```Vec<u8>``` representing any data requested to be hashed
    /// * `return`: ```Vec<u8>``` containaing result of shake operation of size 512 bits
    pub fn compute_sha3_hash(data: &mut Vec<u8>) -> Vec<u8> {
        shake(data, 512)
    }

    /// Computes an authentication tag t of a byte array m under passphrase pw
    /// * `pw`: symmetric encryption key, can be blank but shouldnt be
    /// * `message`: message to encrypt
    /// * `s`: customization string
    /// * `return`: t <- kmac_xof_256(pw, m, 512, “T”) as ```Vec<u8>``` of size `l`
    pub fn compute_tagged_hash(pw: &mut Vec<u8>, message: &mut Vec<u8>, s: &mut str) -> Vec<u8> {
        kmac_xof_256(pw, message, 512, s)
    }

    /// Encrypts a byte array m symmetrically under passphrase pw:
	/// SECURITY NOTE: ciphertext length == plaintext length
    /// * z <- Random(512)
    /// * (ke || ka) <- kmac_xof_256(z || pw, “”, 1024, “S”)
    /// * c <- kmac_xof_256(ke, “”, |m|, “SKE”) xor m
    /// * t <- kmac_xof_256(ka, m, 512, “SKA”)
    /// * `pw`: symmetric encryption key, can be blank but shouldnt be
    /// * `message`: message to encrypt
    /// * `return`: ```SymmetricCryptogram``` (z, c, t)
    pub fn encrypt_with_pw(pw: &mut Vec<u8>, msg: &mut Vec<u8>) -> SymmetricCryptogram{
        let z = get_random_bytes();
        let mut temp_ke_ka = z.clone();
        temp_ke_ka.append(pw);
        let ke_ka = kmac_xof_256(&mut temp_ke_ka, &mut vec![], 1024, "S");
        let mut c = kmac_xof_256(&mut ke_ka[0..ke_ka.len() / 2].to_vec(), &mut vec![], (msg.len() * 8) as u64, "SKE");
        xor_bytes(&mut c, &msg);
        let t = kmac_xof_256(&mut ke_ka[ke_ka.len() / 2..ke_ka.len()].to_vec(), msg, 512, "SKA");
        let cg = SymmetricCryptogram{z,c,t};
        cg
    }

    /// Decrypts a symmetric cryptogram (z, c, t) under passphrase pw.
    /// Assumes that decryption is well-formed. Parsing and error checking
    /// should occur in controller which handles user input.
    /// * (ke || ka) <- kmac_xof_256(z || pw, “”, 1024, “S”)
    /// * m <- kmac_xof_256(ke, “”, |c|, “SKE”) xor c
    /// * t’ <- kmac_xof_256(ka, m, 512, “SKA”)
    /// * `msg`: cryptogram to decrypt as```SymmetricCryptogram```, assumes valid format.
    /// * `pw`: decryption password, can be blank
    /// * `return`: t` == t
    pub fn decrypt_with_pw<'a>(pw: &mut Vec<u8>, msg: & 'a mut SymmetricCryptogram) -> &'a Vec<u8> {
        msg.z.append(pw);
        let ke_ka = kmac_xof_256(&mut msg.z, &mut vec![], 1024, "S");
        let ke = &mut ke_ka[0..ke_ka.len() / 2].to_vec();
        let ka = &mut ke_ka[ke_ka.len() / 2..ke_ka.len()].to_vec();
        let mut dec = kmac_xof_256(ke, &mut vec![], (msg.c.len() * 8) as u64, "SKE");
        let temp = xor_bytes(&mut msg.c, &dec);
        let res = msg.t == kmac_xof_256(ka, &mut dec, 512, "SKA"); //timing issue here?
        temp
    }

    /// Generates a (Schnorr/ECDHIES) key pair from passphrase pw:
    /// 
    /// * s <- kmac_xof_256(pw, “”, 512, “K”); s <- 4s
    /// * V <- s*G
    /// * key pair: (s, V)
    /// * `key` : a pointer to an empty ```KeyObj``` to be populated with user data
    /// * `password` : user-supplied password as ```String```, can be blank but shouldnt be
    /// 
    /// Remark: in the most secure variants of this scheme, the
    /// verification key 𝑉 is hashed together with the message 𝑚
    /// and the nonce 𝑈: hash (𝑚, 𝑈, 𝑉) .
    pub fn gen_keypair(key: &mut KeyObj, password: String, owner: String) {
        let n = set_n();
        let mut pw_bytes = password.as_bytes().to_vec();
        let s = bytes_to_big_int(&kmac_xof_256(&mut pw_bytes, &mut vec![], 512, "K"));
        s.checked_mul(&BigInt::from(4));
        let s = mod_formula(&s, &n);

        let v = get_e521_gen_point(false).sec_mul(s.clone());
        key.owner = owner;
        key.priv_key = s.to_str_radix(10);
        key.pub_key_x = v.x.to_str_radix(10);
        key.pub_key_y = v.y.to_str_radix(10);
        key.date_created = get_date_and_time_as_string();
    }

    /// Encrypts a byte array m under the (Schnorr/ECDHIES) public key V.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// exchanged with recipient. SECURITY NOTE: ciphertext length == plaintext length
    ///
    /// * k <- Random(512); k <- 4k
    /// * W <- k*V; Z <- k*G
    /// * (ke || ka) <- kmac_xof_256(W x , “”, 1024, “P”)
    /// * c <- kmac_xof_256(ke, “”, |m|, “PKE”) xor m
    /// * t <- kmac_xof_256(ka, m, 512, “PKA”)
    /// * `pub_key` : X coordinate of public static key V, accepted as ```E521```
    /// * `message`: message of any length or format to encrypt
    /// * `return` : cryptogram: (Z, c, t) = Z||c||t
    pub fn encrypt_with_key(pub_key: &mut E521, message: &Vec<u8>) -> ECCryptogram{
        let mut k = bytes_to_big_int(&get_random_bytes()).mul(BigInt::from(4));
        k = mod_formula(&k, &set_n());
    
        let w= pub_key.sec_mul(k.clone());
        let z = get_e521_gen_point(false).sec_mul(k.clone());
        
        let (_, mut temp) = w.x.to_bytes_be(); //change to le if this fails
        let ke_ka = kmac_xof_256(&mut temp, &mut vec![], 1024, "P");
        let ke = &mut ke_ka[0..ke_ka.len() / 2].to_vec();
        let ka = &mut ke_ka[ke_ka.len() / 2..ke_ka.len()].to_vec();
        xor_bytes(&mut kmac_xof_256(ke, &mut vec![], (message.len()*8) as u64, "PKE"), &message);
        let cryptogram = ECCryptogram{
            z_x: z.x, 
            z_y: z.y, 
            c: message.clone(), 
            t: kmac_xof_256(&mut ka.clone(), &mut message.clone(), 512, "PKA")};
        cryptogram
    }

}