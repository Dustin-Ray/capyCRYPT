pub mod shake_functions {
    use crate::curve::Curves;
    use crate::curve::{curve_n, CurvePoint, Generator, Point};
    use crate::sha3::aux_functions::byte_utils::{
        big_to_bytes, bytes_to_big, get_date_and_time_as_string, get_random_bytes, xor_bytes,
    };
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};
    use crate::sha3::sponge::sponge_function::{sponge_absorb, sponge_squeeze};
    use crate::{ECCryptogram, KeyObj, Signature, SymmetricCryptogram};
    use rug::Integer;
    use std::borrow::{Borrow, BorrowMut};

    const SELECTED_CURVE: Curves = Curves::E448;

    /// # SHA3-Keccak
    /// ref NIST FIPS 202.
    /// ## Arguments:
    /// * `n: &mut Vec<u8>`: pointer to message to be hashed.
    /// * `d: usize`: requested output length
    /// ## Returns:
    /// * `return  -> Vec<u8>`: SHA3-512 message digest
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
            return shake(x, l);
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
    /// * `k: &mut Vec<u8>`: key
    /// * `x: &mut Vec<u8>`: byte-oriented message
    /// * `l: u64`: requested bit output length
    /// * `s: &str`: customization string
    /// ## Returns:
    /// * `return  -> Vec<u8>`: kmac_xof of `x` under `k`
    pub fn kmac_xof(k: &mut Vec<u8>, x: &mut Vec<u8>, l: u64, s: &str, d: u64) -> Vec<u8> {
        let mut encode_k = encode_string(k);
        let bytepad_w = match d {
            256 => 168,
            512 => 136,
            _ => panic!("Value must be either 256 or 512"),
        };
        let mut bp = byte_pad(&mut encode_k, bytepad_w);
        bp.append(x); //x is dropped here?
        let mut right_enc = right_encode(0);
        bp.append(&mut right_enc);
        cshake(&mut bp, l, "KMAC", s, d)
    }

    /// # Message Digest
    /// Computes SHA3-512 hash of input
    /// ## Arguments:
    /// * `data: &mut Vec<u8>`: representing any data requested to be hashed
    /// ## Returns:
    /// * `return  -> Vec<u8>`: containaing result of shake operation of size 512 bits
    pub fn compute_sha3_hash(data: &mut Vec<u8>) -> Vec<u8> {
        shake(data, 512)
    }

    /// # Tagged Hash
    /// Computes an authentication tag `t` of a byte array `m` under passphrase `pw`
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>`: symmetric encryption key, can be blank but shouldnt be
    /// * `message: &mut Vec<u8>`: message to encrypt
    /// * `s: &mut str`: customization string
    /// ## Returns:
    /// * `return  -> Vec<u8>`: `t` ← kmac_xof(pw, m, 512, “T”) as ```Vec<u8>``` of size `l`
    pub fn compute_tagged_hash(pw: &mut Vec<u8>, message: &mut Vec<u8>, s: &mut str) -> Vec<u8> {
        kmac_xof(pw, message, 512, s, 512)
    }

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
    pub fn encrypt_with_pw(
        pw: &mut Vec<u8>,
        msg: &mut Box<Vec<u8>>,
        d: u64,
    ) -> SymmetricCryptogram {
        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.append(pw);
        let ke_ka = kmac_xof(&mut ke_ka, &mut vec![], 1024, "S", d);
        let mut ke = ke_ka[..64].to_vec();
        let mut c = kmac_xof(&mut ke, &mut vec![], (&msg.len() * 8) as u64, "SKE", d);
        xor_bytes(&mut c, msg.borrow_mut());
        let t = kmac_xof(&mut ke_ka[64..].to_vec(), msg.borrow_mut(), 512, "SKA", d);
        SymmetricCryptogram { z, c, t }
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
    pub fn decrypt_with_pw(pw: &mut Vec<u8>, msg: &mut Box<SymmetricCryptogram>, d: u64) -> bool {
        msg.z.append(pw);
        let ke_ka = kmac_xof(&mut msg.z, &mut vec![], 1024, "S", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let m = kmac_xof(ke, &mut vec![], (msg.c.len() * 8) as u64, "SKE", d);
        xor_bytes(&mut msg.c, &m);
        msg.t == kmac_xof(ka, msg.c.borrow_mut(), 512, "SKA", d)
    }

    /// # Asymmetric Keypair Generation
    /// Generates a (Schnorr/ECDHIES) key pair from passphrase pw:
    /// ## Algorithm:
    /// * s ← kmac_xof(pw, “”, 512, “K”); s ← 4s
    /// * 𝑉 ← s*𝑮
    /// * key pair: (s, 𝑉)
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>` : password as bytes, can be blank but shouldnt be
    /// * `owner: String` : A label to indicate the owner of the key
    /// * Remark: in the most secure variants of this scheme, the
    /// ## Returns:
    /// * `return  -> KeyObj`: Key object containing owner, private key, public key x and y coordinates, and timestamp.
    /// verification key 𝑉 is hashed together with the message 𝑚
    /// and the nonce 𝑈: hash (𝑚, 𝑈, 𝑉) .
    pub fn gen_keypair(pw: &mut Vec<u8>, owner: String, d: u64) -> KeyObj {
        let s: Integer =
            (bytes_to_big(kmac_xof(pw, &mut vec![], 512, "K", d)) * 4) % curve_n(SELECTED_CURVE);
        let v = CurvePoint::generator(SELECTED_CURVE, false) * (s);
        KeyObj {
            owner,
            priv_key: pw.to_vec(),
            pub_x: v.x,
            pub_y: v.y,
            date_created: get_date_and_time_as_string(),
        }
    }

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
    /// * `pub_key: E521` : X coordinate of public static key 𝑉, accepted as ```E521```
    /// * `message: &mut Box<Vec<u8>>`: borrowed pointer to message of any length
    /// ## Returns:
    /// * `return -> ECCryptogram` : cryptogram: (𝑍, c, t) = 𝑍||c||t
    pub fn encrypt_with_key(
        pub_key: CurvePoint,
        message: &mut Box<Vec<u8>>,
        d: u64,
    ) -> ECCryptogram {
        let k: Integer = (bytes_to_big(get_random_bytes(64)) * 4) % curve_n(SELECTED_CURVE);
        let w = pub_key * k.clone();
        let z = CurvePoint::generator(SELECTED_CURVE, false) * k;
        let ke_ka = kmac_xof(&mut big_to_bytes(w.x), &mut vec![], 1024, "PK", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();

        let len = (message.len() * 8) as u64;
        let mut c = kmac_xof(ke, &mut vec![], len, "PKE", d);
        xor_bytes(&mut c, message);
        let t = kmac_xof(&mut ka.clone(), message.borrow_mut(), 512, "PKA", d);

        ECCryptogram {
            z_x: z.x,
            z_y: z.y,
            c,
            t,
        }
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
    /// * `pw: &mut [u8]`: password used to generate ```E521``` encryption key.
    /// * `message: &mut ECCryptogram`: cryptogram of format ```(𝑍||c||t)```
    /// ## Returns:
    /// * `return  -> bool`: Decryption of cryptogram ```𝑍||c||t iff t` = t```
    pub fn decrypt_with_key(pw: &mut [u8], message: &mut ECCryptogram, d: u64) -> bool {
        let z = CurvePoint::point(SELECTED_CURVE, message.z_x.clone(), message.z_y.clone());
        let s: Integer = (bytes_to_big(kmac_xof(&mut pw.to_owned(), &mut vec![], 512, "K", d)) * 4)
            % z.clone().n;

        let w = z * s;
        let ke_ka = kmac_xof(&mut big_to_bytes(w.x), &mut vec![], 1024, "PK", d);
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let len = message.c.len() * 8;
        let m = Box::new(kmac_xof(ke, &mut vec![], (len) as u64, "PKE", d));
        xor_bytes(&mut message.c, m.borrow());
        let t_p = kmac_xof(&mut ka.clone(), &mut message.c, 512, "PKA", d);
        t_p == message.t
    }

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
    pub fn sign_with_key(pw: &mut Vec<u8>, message: &mut Box<Vec<u8>>, d: u64) -> Signature {
        let s: Integer = bytes_to_big(kmac_xof(pw, &mut vec![], 512, "K", d)) * 4;
        let mut s_bytes = big_to_bytes(s.clone());

        let k: Integer =
            bytes_to_big(kmac_xof(&mut s_bytes, message.borrow_mut(), 512, "N", d)) * 4;

        let u = CurvePoint::generator(SELECTED_CURVE, false) * k.clone();
        let mut ux_bytes = big_to_bytes(u.x);
        let h = kmac_xof(&mut ux_bytes, message.borrow_mut(), 512, "T", d);
        let h_big = bytes_to_big(h.clone());
        //(a % b + b) % b
        let z = ((k - (h_big * s)) % u.r.clone() + u.r.clone()) % u.r;
        Signature { h, z }
    }

    /// # Signature Verification
    /// Verifies a signature (h, 𝑍) for a byte array m under the (Schnorr/
    /// ECDHIES) public key 𝑉:
    /// ## Algorithm:
    /// * 𝑈 ← 𝑍*𝑮 + h𝑉
    /// ## Arguments:
    /// * `sig: &Signature`: Pointer to a signature object (h, 𝑍)
    /// * `pubKey: E521` key 𝑉 used to sign message m
    /// * `message: Vec<u8>` of message to verify
    /// ## Returns:
    /// * `return`: true if, and only if, kmac_xof(𝑈ₓ , m, 512, “T”) = h
    pub fn verify_signature(
        sig: &Signature,
        pub_key: CurvePoint,
        message: &mut Box<Vec<u8>>,
        d: u64,
    ) -> bool {
        let mut u = CurvePoint::generator(SELECTED_CURVE, false) * sig.z.clone();
        let hv = pub_key * (bytes_to_big(sig.h.clone()));
        u = u + hv;
        let h_p = kmac_xof(&mut big_to_bytes(u.x), message.borrow_mut(), 512, "T", d);
        h_p == sig.h
    }
}
