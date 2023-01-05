pub mod shake_functions {
    use std::mem;
    use crate::sha3::aux_functions::arith::mod_formula;
    use crate::{SymmetricCryptogram, KeyObj, ECCryptogram, E521};
    use crate::curve::e521::e521_module::{set_r, get_e521_gen_point, PointOps, get_e521_point};
    use crate::sha3::sponge::sponge_function::{sponge_squeeze, sponge_absorb};
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};
    use crate::sha3::aux_functions::byte_utils::{
        xor_bytes, 
        get_random_bytes, 
        get_date_and_time_as_string, 
        bytes_to_big, big_to_bytes, get_random_big};
    
    /// SHA3-Keccak ref NIST FIPS 202.
    /// * `n`: pointer to message to be hashed.
    /// * `d`: requested output length
    fn shake(n: &mut Vec<u8>, d: usize) -> Vec<u8> {
        let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
        if bytes_to_pad == 1 { n.extend_from_slice(&[0x86]);} //delim suffix
        else { n.extend_from_slice(&[0x06]);} //delim suffix
        sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600-(2*d))
    }
 
    /// FIPS 202 Section 3 cSHAKE function returns customizable and
    /// domain seperated length L SHA3XOF hash of input string.
    /// * `x`: input message as ```Vec<u8>```
    /// * `l`: requested output length
    /// * `n`: optional function name string
    /// * `s`: option customization string
    /// * `return`: SHA3XOF hash of length `l` of input message `x`
    pub fn cshake(x: &mut Vec<u8>, l: u64, n: &str, s: &str) -> Vec<u8> {
        if n.is_empty() && s.is_empty() { return shake(x, l as usize) }
        let mut encoded_n = encode_string(&mut n.as_bytes().to_vec());
        let encoded_s = encode_string(&mut s.as_bytes().to_vec());
        encoded_n.extend_from_slice(&encoded_s);
        let mut out = byte_pad(&mut encoded_n, 136);
        out.append(x);
        out.push(0x04);
        sponge_squeeze(&mut sponge_absorb(&mut out, 512), l as usize, 1600-512)
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
        cshake(&mut bp, l, "KMAC", s)
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
        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.append(pw);
        let ke_ka = kmac_xof_256(&mut ke_ka, &mut vec![], 1024, "S");
        let mut c = kmac_xof_256(&mut ke_ka[..64].to_vec(), &mut vec![], (msg.len() * 8) as u64, "SKE");
        xor_bytes(&mut c, msg);
        let t = kmac_xof_256(&mut ke_ka[64..].to_vec(), msg, 512, "SKA");
        SymmetricCryptogram{z,c,t}

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
    pub fn decrypt_with_pw(pw: &mut Vec<u8>, msg: &mut SymmetricCryptogram) -> bool {
        msg.z.append(pw);
        let ke_ka = kmac_xof_256(&mut msg.z, &mut vec![], 1024, "S");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let m = kmac_xof_256(ke, &mut vec![], (msg.c.len() * 8) as u64, "SKE");
        xor_bytes(&mut msg.c, &m);
        msg.t == kmac_xof_256(ka, &mut msg.c.clone(), 512, "SKA")
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
    pub fn gen_keypair(pw: &mut [u8], owner: String) -> KeyObj {
        let mut s = bytes_to_big(kmac_xof_256(&mut pw.to_owned(), &mut vec![], 512, "K")) * 4;
        s = mod_formula(s, set_r());
        
        let v = get_e521_gen_point(false).sec_mul(s);
        KeyObj{
            owner,
            priv_key: pw.to_vec(),
            pub_key_x: v.x,
            pub_key_y: v.y,
            date_created: get_date_and_time_as_string(),
        }
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
    pub fn encrypt_with_key(pub_key: &mut E521, message: &mut Vec<u8>) -> ECCryptogram{
        
        let k = mod_formula(get_random_big(512) * 4, set_r());
        let w= pub_key.sec_mul(k.clone());
        let z = get_e521_gen_point(false).sec_mul(k);

        let ke_ka = kmac_xof_256(&mut big_to_bytes(w.x), &mut vec![], 1024, "P");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let t = kmac_xof_256(&mut ka.clone(), &mut message.clone(), 512, "PKA");
        xor_bytes(message, &kmac_xof_256(ke, &mut vec![], (message.len()*8) as u64, "PKE"));
        ECCryptogram{
        z_x: z.x.clone(), 
        z_y: z.y, 
        c: mem::take(message), 
        t}    
    }

    /// Decrypts a cryptogram under password. Assumes cryptogram is well-formed.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// derived from Z.
    /// * s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
    /// * W <- s*Z
    /// * (ke || ka) <- KMACXOF256(W x , “”, 1024, “P”)
    /// * m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
    /// * t’ <- KMACXOF256(ka, m, 512, “PKA”)
    /// * `pw`: password used to generate ```E521``` encryption key.
    /// * `message`: cryptogram of format Z||c||t
    /// * `return`: Decryption of cryptogram Z||c||t iff t` = t
    pub fn decrypt_with_key(pw: &mut [u8], message: ECCryptogram) -> bool {

        let mut z = get_e521_point(message.z_x.clone(), message.z_y.clone());
        let mut s = bytes_to_big(kmac_xof_256(&mut pw.to_owned(), &mut vec![], 512, "K")) * 4;
        s = mod_formula(s, set_r());
        let w = z.sec_mul(s);
        let ke_ka = kmac_xof_256(&mut big_to_bytes(w.x), &mut vec![], 1024, "P");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();            
        let len = message.c.len() * 8;
        let mut m = kmac_xof_256(ke, &mut vec![], (len) as u64, "PKE");
        xor_bytes(&mut m, &message.c);
        let t_p = kmac_xof_256(&mut ka.clone(), &mut m, 512, "PKA");
        t_p == message.t
    }


}