pub mod shake_functions {

    use crate::curve::e521::e521_module::{get_e521_gen_point, get_e521_point, get_n};
    use crate::sha3::aux_functions::byte_utils::{
        big_to_bytes, bytes_to_big, get_date_and_time_as_string, get_random_bytes, xor_bytes,
    };
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};
    use crate::sha3::sponge::sponge_function::{sponge_absorb, sponge_squeeze};
    use crate::{ECCryptogram, KeyObj, Signature, SymmetricCryptogram, E521};
    use rug::Integer;
    use std::borrow::{Borrow, BorrowMut};

    /// SHA3-Keccak ref NIST FIPS 202.
    /// * `n`: pointer to message to be hashed.
    /// * `d`: requested output length
    fn shake(n: &mut Vec<u8>, d: usize) -> Vec<u8> {
        let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
        if bytes_to_pad == 1 {
            n.extend_from_slice(&[0x86]);
        }
        //delim suffix
        else {
            n.extend_from_slice(&[0x06]);
        } //delim suffix
        sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600 - (2 * d))
    }

    /// FIPS 202 Section 3 cSHAKE function returns customizable and
    /// domain seperated length L SHA3XOF hash of input string.
    /// * `x`: input message as ```Vec<u8>```
    /// * `l`: requested output length
    /// * `n`: optional function name string
    /// * `s`: option customization string
    /// * `return`: SHA3XOF hash of length `l` of input message `x`
    pub fn cshake(x: &mut Vec<u8>, l: u64, n: &str, s: &str) -> Vec<u8> {
        if n.is_empty() && s.is_empty() {
            return shake(x, l as usize);
        }
        let mut encoded_n = encode_string(&mut n.as_bytes().to_vec());
        let encoded_s = encode_string(&mut s.as_bytes().to_vec());
        encoded_n.extend_from_slice(&encoded_s);
        let mut out = byte_pad(&mut encoded_n, 136);
        out.append(x);
        out.push(0x04);
        sponge_squeeze(&mut sponge_absorb(&mut out, 512), l as usize, 1600 - 512)
    }

    /// Generates keyed hash for given input as specified in NIST SP 800-185 section 4.
    /// * `k`: key
    /// * `x`: byte-oriented message
    /// * `l`: requested bit length
    /// * `s`: customization string
    /// * `return`: kmac_xof_256 of `x` under `k`
    pub fn kmac_xof_256(k: &mut Vec<u8>, x: &mut Vec<u8>, l: u64, s: &str) -> Vec<u8> {
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
    /// * `return`: t ← kmac_xof_256(pw, m, 512, “T”) as ```Vec<u8>``` of size `l`
    pub fn compute_tagged_hash(pw: &mut Vec<u8>, message: &mut Vec<u8>, s: &mut str) -> Vec<u8> {
        kmac_xof_256(pw, message, 512, s)
    }

    /// Encrypts a byte array m symmetrically under passphrase pw:
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// * z ← Random(512)
    /// * (ke || ka) ← kmac_xof_256(z || pw, “”, 1024, “S”)
    /// * c ← kmac_xof_256(ke, “”, |m|, “SKE”) ⊕ m
    /// * t ← kmac_xof_256(ka, m, 512, “SKA”)
    /// * `pw`: symmetric encryption key, can be blank but shouldnt be
    /// * `message`: message to encrypt
    /// * `return`: ```SymmetricCryptogram``` (z, c, t)
    pub fn encrypt_with_pw(pw: &mut Vec<u8>, msg: &mut Box<Vec<u8>>) -> SymmetricCryptogram {
        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.append(pw);
        let ke_ka = kmac_xof_256(&mut ke_ka, &mut vec![], 1024, "S");
        let mut ke = ke_ka[..64].to_vec();
        let mut c = kmac_xof_256(&mut ke, &mut vec![], (&msg.len() * 8) as u64, "SKE");
        xor_bytes(&mut c, msg.borrow_mut());
        let t = kmac_xof_256(&mut ke_ka[64..].to_vec(), msg.borrow_mut(), 512, "SKA");
        SymmetricCryptogram { z, c, t }
    }

    /// Decrypts a symmetric cryptogram (z, c, t) under passphrase pw.
    /// Assumes that decryption is well-formed. Parsing and error checking
    /// should occur in controller which handles user input.
    /// * (ke || ka) ← kmac_xof_256(z || pw, “”, 1024, “S”)
    /// * m ← kmac_xof_256(ke, “”, |c|, “SKE”) ⊕ c
    /// * t’ ← kmac_xof_256(ka, m, 512, “SKA”)
    /// * `msg`: cryptogram to decrypt as```SymmetricCryptogram```, assumes valid format.
    /// * `pw`: decryption password, can be blank
    /// * `return`: t` == t
    pub fn decrypt_with_pw(pw: &mut Vec<u8>, msg: &mut Box<SymmetricCryptogram>) -> bool {
        msg.z.append(pw);
        let ke_ka = kmac_xof_256(&mut msg.z, &mut vec![], 1024, "S");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let m = kmac_xof_256(ke, &mut vec![], (msg.c.len() * 8) as u64, "SKE");
        xor_bytes(&mut msg.c, &m);
        msg.t == kmac_xof_256(ka, msg.c.borrow_mut(), 512, "SKA")
    }

    /// Generates a (Schnorr/ECDHIES) key pair from passphrase pw:
    ///
    /// * s ← kmac_xof_256(pw, “”, 512, “K”); s ← 4s
    /// * 𝑉 ← sG
    /// * key pair: (s, 𝑉)
    /// * `key` : a pointer to an empty ```KeyObj``` to be populated with user data
    /// * `password` : user-supplied password as ```String```, can be blank but shouldnt be
    ///
    /// Remark: in the most secure variants of this scheme, the
    /// verification key 𝑉 is hashed together with the message 𝑚
    /// and the nonce 𝑈: hash (𝑚, 𝑈, 𝑉) .
    pub fn gen_keypair(pw: &mut Vec<u8>, owner: String) -> KeyObj {
        let s: Integer = (bytes_to_big(kmac_xof_256(pw, &mut vec![], 512, "K")) * 4) % get_n();
        let v = get_e521_gen_point(false) * (s);
        KeyObj {
            owner,
            priv_key: pw.to_vec(),
            pub_x: v.x,
            pub_y: v.y,
            date_created: get_date_and_time_as_string(),
        }
    }

    /// Encrypts a byte array m under the (Schnorr/ECDHIES) public key 𝑉.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// exchanged with recipient. SECURITY NOTE: ciphertext length == plaintext length
    ///
    /// * k ← Random(512); k ← 4k
    /// * W ← kV; 𝑍 ← k*G
    /// * (ke || ka) ← kmac_xof_256(W x , “”, 1024, “P”)
    /// * c ← kmac_xof_256(ke, “”, |m|, “PKE”) ⊕ m
    /// * t ← kmac_xof_256(ka, m, 512, “PKA”)
    /// * `pub_key` : X coordinate of public static key 𝑉, accepted as ```E521```
    /// * `message`: message of any length or format to encrypt
    /// * `return` : cryptogram: (𝑍, c, t) = 𝑍||c||t
    pub fn encrypt_with_key(pub_key: E521, message: &mut Box<Vec<u8>>) -> ECCryptogram {
        let k: Integer = (bytes_to_big(get_random_bytes(64)) * 4) % get_n();
        let w = pub_key * k.clone();
        let z = get_e521_gen_point(false) * k;
        let ke_ka = kmac_xof_256(&mut big_to_bytes(w.x), &mut vec![], 1024, "P");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();

        let len = (message.len() * 8) as u64;
        let mut c = kmac_xof_256(ke, &mut vec![], len, "PKE");
        xor_bytes(&mut c, message);
        let t = kmac_xof_256(&mut ka.clone(), message.borrow_mut(), 512, "PKA");

        ECCryptogram {
            z_x: z.x,
            z_y: z.y,
            c,
            t,
        }
    }

    /// Decrypts a cryptogram under password. Assumes cryptogram is well-formed.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// derived from 𝑍.
    /// * s ← KMACXOF256(pw, “”, 512, “K”); s ← 4s
    /// * W ← sZ
    /// * (ke || ka) ← KMACXOF256(W x , “”, 1024, “P”)
    /// * m ← KMACXOF256(ke, “”, |c|, “PKE”) ⊕ c
    /// * t’ ← KMACXOF256(ka, m, 512, “PKA”)
    /// * `pw`: password used to generate ```E521``` encryption key.
    /// * `message`: cryptogram of format 𝑍||c||t
    /// * `return`: Decryption of cryptogram 𝑍||c||t iff t` = t
    pub fn decrypt_with_key(pw: &mut [u8], message: &mut ECCryptogram) -> bool {
        let z = get_e521_point(message.z_x.clone(), message.z_y.clone());
        let s: Integer =
            (bytes_to_big(kmac_xof_256(&mut pw.to_owned(), &mut vec![], 512, "K")) * 4) % get_n();

        let w = z * s;
        let ke_ka = kmac_xof_256(&mut big_to_bytes(w.x), &mut vec![], 1024, "P");
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let len = message.c.len() * 8;
        let m = Box::new(kmac_xof_256(ke, &mut vec![], (len) as u64, "PKE"));
        xor_bytes(&mut message.c, m.borrow());
        let t_p = kmac_xof_256(&mut ka.clone(), &mut message.c, 512, "PKA");
        t_p == message.t
    }

    /// Generates a signature for a byte array m under passphrase pw:
    /// * `s` ← kmac_xof_256(pw, “”, 512, “K”); s ← 4s
    /// * `k` ← kmac_xof_256(s, m, 512, “N”); k ← 4k
    /// * `𝑈` ← kG;
    /// * `h` ← kmac_xof_256(𝑈ₓ , m, 512, “T”); z ← (𝑘 – ℎ𝑠) mod r
    /// * `return`: signature: (`h`, `z`)
    pub fn sign_with_key(pw: &mut Vec<u8>, message: &mut Box<Vec<u8>>) -> Signature {
        let s: Integer = bytes_to_big(kmac_xof_256(pw, &mut vec![], 512, "K")) * 4;
        let mut s_bytes = big_to_bytes(s.clone());

        let k: Integer =
            bytes_to_big(kmac_xof_256(&mut s_bytes, message.borrow_mut(), 512, "N")) * 4;

        let u = get_e521_gen_point(false) * k.clone();
        let mut ux_bytes = big_to_bytes(u.x);
        let h = kmac_xof_256(&mut ux_bytes, message.borrow_mut(), 512, "T");
        let h_big = bytes_to_big(h.clone());
        //(a % b + b) % b
        let z = ((k - (h_big * s)) % u.r.clone() + u.r.clone()) % u.r;
        Signature { h, z }
    }

    /// Verifies a signature (h, z) for a byte array m under the (Schnorr/
    /// ECDHIES) public key 𝑉:
    /// * 𝑈 ← zG + h𝑉
    /// * `sig`: signature: (h, z)
    /// * `pubKey`: E521 key 𝑉 used to sign message m
    /// * `message`: Vec<u8> of message to verify
    /// * `return`: true if, and only if, kmac_xof_256(𝑈ₓ , m, 512, “T”) = h
    pub fn verify_signature(sig: &Signature, pub_key: E521, message: &mut Box<Vec<u8>>) -> bool {
        let mut u = get_e521_gen_point(false) * sig.z.clone();
        let hv = pub_key * (bytes_to_big(sig.h.clone()));
        u = u + hv;
        let mut ux_bytes = big_to_bytes(u.x);
        let h_p = kmac_xof_256(&mut ux_bytes, message.borrow_mut(), 512, "T");
        h_p == sig.h
    }
}
