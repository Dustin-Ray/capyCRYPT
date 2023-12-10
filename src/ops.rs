use crate::{
    curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar},
    sha3::{
        aux_functions::{
            byte_utils::{
                bytes_to_scalar, get_date_and_time_as_string, get_random_bytes, scalar_to_bytes,
                xor_bytes,
            },
            nist_800_185::{byte_pad, encode_string, right_encode},
        },
        sponge::{sponge_absorb, sponge_squeeze},
    },
    AesEncryptable, Hashable, KeyEncryptable, KeyPair, Message, PwEncryptable, Signable, Signature,
};

// ============================================================
// The main components of the cryptosystem are defined here
// as trait implementations on specific types. The types and
// their traits are defined in lib.rs. The arguments to all
// operations mirror the notation from NIST FIPS 202 wherever
// possible.

// The Message type contains a data field. All operations are
// performed IN PLACE.
// ============================================================

/// # SHA3-Keccak
/// ref NIST FIPS 202.
/// ## Arguments:
/// * `n: &mut Vec<u8>`: reference to message to be hashed.
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
/// * `x: &Vec<u8>`: input message as ```Vec<u8>```
/// * `l: u64`: requested output length
/// * `n: &str`: optional function name string
/// * `s: &str`: option customization string
/// ## Returns:
/// * `return -> Vec<u8>`: SHA3XOF hash of length `l` of input message `x`
pub fn cshake(x: &[u8], l: u64, n: &str, s: &str, d: u64) -> Vec<u8> {
    let mut encoded_n = encode_string(&n.as_bytes().to_vec());
    let encoded_s = encode_string(&s.as_bytes().to_vec());
    encoded_n.extend_from_slice(&encoded_s);

    let bytepad_w = match d {
        224 => 172,
        256 => 168,
        384 => 152,
        512 => 136,
        _ => panic!("Unsupported security strength. Must be 224, 384, 256, or 512"),
    };

    let mut out = byte_pad(&mut encoded_n, bytepad_w);
    out.extend_from_slice(x);
    out.push(0x04);

    if n.is_empty() && s.is_empty() {
        shake(&mut out, l);
    }

    sponge_squeeze(&mut sponge_absorb(&mut out, d), l, 1600 - d)
}

/// # Keyed Message Authtentication
/// Generates keyed hash for given input as specified in NIST SP 800-185 section 4.
/// ## Arguments:
/// * `k: &Vec<u8>`: key. SP 800 185 8.4.1 KMAC Key Length requires key length >= d
/// * `x: &Vec<u8>`: byte-oriented message
/// * `l: u64`: requested bit output length
/// * `s: &str`: customization string
/// * `d: u64`: the security parameter for the operation. NIST-standard values for d consist of the following:
/// d = 512; 256 bits of security
/// d = 256; 128 bits of security
///
/// ## Returns:
/// * `return  -> Vec<u8>`: kmac_xof of `x` under `k`
pub fn kmac_xof(k: &Vec<u8>, x: &[u8], l: u64, s: &str, d: u64) -> Vec<u8> {
    let mut encode_k = encode_string(k);
    let bytepad_w = match d {
        224 => 172,
        256 => 168,
        384 => 152,
        512 => 136,
        _ => panic!("Unsupported security strength. Must be 224, 384, 256, or 512"),
    };
    let mut bp = byte_pad(&mut encode_k, bytepad_w);

    // Extend bp with contents of x and right_encode(0)
    bp.extend_from_slice(x);
    bp.extend_from_slice(&right_encode(0)); // SP 800-185 4.3.1 KMAC with Arbitrary-Length Output

    cshake(&bp, l, "KMAC", s, d)
}

impl Hashable for Message {
    /// # Message Digest
    /// Computes SHA3-d hash of input. Does not consume input.
    /// Replaces `Message.digest` with result of operation.
    /// ## Arguments:
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// use capycrypt::{Hashable, Message};
    /// // Hash the empty string
    /// let mut data = Message::new(vec![]);
    /// // Obtained from echo -n "" | openssl dgst -sha3-256
    /// let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    /// // Compute a SHA3 digest with 128 bits of security
    /// data.compute_hash_sha3(256);
    /// assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
    /// ```
    fn compute_hash_sha3(&mut self, d: u64) {
        self.digest = match d {
            224 | 256 | 384 | 512 => Some(shake(&mut self.msg, d)),
            _ => panic!("Value must be either 224, 256, 384, or 512"),
        }
    }

    /// # Tagged Hash
    /// Computes an authentication tag `t` of a byte array `m` under passphrase `pw`.
    /// ## Replaces:
    /// * `Message.t` with keyed hash of plaintext.
    /// ## Arguments:
    /// * `pw: &mut Vec<u8>`: symmetric encryption key, can be blank but shouldnt be
    /// * `message: &mut Vec<u8>`: message to encrypt
    /// * `s: &mut str`: domain seperation string
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// use capycrypt::{Hashable, Message};
    /// let mut pw = "test".as_bytes().to_vec();
    /// let mut data = Message::new(vec![]);
    /// let expected = "0f9b5dcd47dc08e08a173bbe9a57b1a65784e318cf93cccb7f1f79f186ee1caeff11b12f8ca3a39db82a63f4ca0b65836f5261ee64644ce5a88456d3d30efbed";
    /// data.compute_tagged_hash(&mut pw, &"", 512);
    /// assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
    /// ```
    fn compute_tagged_hash(&mut self, pw: &mut Vec<u8>, s: &str, d: u64) {
        self.digest = match d {
            224 | 256 | 384 | 512 => Some(kmac_xof(pw, &self.msg, d, s, d)),
            _ => panic!("Value must be either 224, 256, 384, or 512"),
        }
    }
}

impl PwEncryptable for Message {
    /// # Symmetric Encryption
    /// Encrypts a [`Message`] m symmetrically under passphrase pw.
    /// ## Replaces:
    /// * `Message.data` with result of encryption.
    /// * `Message.t` with keyed hash of plaintext.
    /// * `Message.sym_nonce` with z, as defined below.
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * z ← Random(512)
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * c ← kmac_xof(ke, “”, |m|, “SKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &[u8]`: symmetric encryption key, can be blank but shouldnt be
    /// * `d: u64`: requested security strength in bits. Supported
    /// bitstrengths are 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// use capycrypt::{
    ///     Message,
    ///     PwEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}}
    /// };
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.pw_encrypt_sha3(&pw, 512);
    /// // Decrypt the data
    /// msg.pw_decrypt_sha3(&pw);
    /// // Verify operation success
    /// assert!(msg.op_result.unwrap());
    /// ```
    fn pw_encrypt_sha3(&mut self, pw: &[u8], d: u64) {
        self.d = Some(d);
        let z = get_random_bytes(512);
        let mut ke_ka = z.clone();
        ke_ka.append(&mut pw.to_owned());
        let ke_ka = kmac_xof(&ke_ka, &[], 1024, "S", d);
        let ke = &ke_ka[..64].to_vec();
        let ka = &ke_ka[64..].to_vec();
        self.digest = Some(kmac_xof(ka, &self.msg, 512, "SKA", d));
        let c = kmac_xof(ke, &[], (self.msg.len() * 8) as u64, "SKE", d);
        xor_bytes(&mut self.msg, &c);
        self.sym_nonce = Some(z);
    }

    /// # Symmetric Decryption
    /// Decrypts a [`Message`] (z, c, t) under passphrase pw.
    /// ## Assumes:
    /// * well-formed encryption
    /// * Some(Message.t)
    /// * Some(Message.z)
    /// ## Replaces:
    /// * `Message.data` with result of decryption.
    /// * `Message.op_result` with result of comparision of `Message.t` == keyed hash of decryption.
    /// ## Algorithm:
    /// * (ke || ka) ← kmac_xof(z || pw, “”, 1024, “S”)
    /// * m ← kmac_xof(ke, “”, |c|, “SKE”) ⊕ c
    /// * t’ ← kmac_xof(ka, m, 512, “SKA”)
    /// ## Arguments:
    /// * `pw: &[u8]`: decryption password, can be blank
    /// ## Usage:
    /// ```
    /// use capycrypt::{
    ///     Message,
    ///     PwEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}}
    /// };
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.pw_encrypt_sha3(&pw, 512);
    /// // Decrypt the data
    /// msg.pw_decrypt_sha3(&pw);
    /// // Verify operation success
    /// assert!(msg.op_result.unwrap());
    /// ```
    fn pw_decrypt_sha3(&mut self, pw: &[u8]) {
        let mut z_pw = self.sym_nonce.clone().unwrap();
        z_pw.append(&mut pw.to_owned());
        let ke_ka = kmac_xof(&z_pw, &[], 1024, "S", self.d.unwrap());
        let ke = &mut ke_ka[..64].to_vec();
        let ka = &mut ke_ka[64..].to_vec();
        let m = kmac_xof(ke, &[], (self.msg.len() * 8) as u64, "SKE", self.d.unwrap());
        xor_bytes(&mut self.msg, &m);
        let new_t = &kmac_xof(ka, &self.msg, 512, "SKA", self.d.unwrap());
        self.op_result = Some(self.digest.as_mut().unwrap() == new_t);
    }
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
    /// ## Usage:
    /// ```  
    /// ```
    #[allow(non_snake_case)]
    pub fn new(pw: &Vec<u8>, owner: String, d: u64) -> KeyPair {
        // ensure a fixed-bitsize to mitigate sidechannel
        let s: Scalar =
            bytes_to_scalar(kmac_xof(pw, &[], 448, "SK", d)).mul_mod_r(&Scalar::from(4_u64));

        let V = ExtendedPoint::tw_generator() * s;

        KeyPair {
            owner,
            pub_key: V,
            priv_key: pw.to_vec(),
            date_created: get_date_and_time_as_string(),
        }
    }
}

impl KeyEncryptable for Message {
    /// # Asymmetric Encryption
    /// Encrypts a [`Message`] in place under the (Schnorr/ECDHIES) public key 𝑉.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// exchanged with recipient. SECURITY NOTE: ciphertext length == plaintext length
    /// ## Replaces:
    /// * `Message.data` with result of encryption.
    /// * `Message.t` with keyed hash of plaintext.
    /// * `Message.asym_nonce` with z, as defined below.
    /// ## Algorithm:
    /// * k ← Random(448); k ← 4k
    /// * W ← kV; 𝑍 ← k*𝑮
    /// * (ke || ka) ← kmac_xof(W x , “”, 448 * 2, “P”)
    /// * c ← kmac_xof(ke, “”, |m|, “PKE”) ⊕ m
    /// * t ← kmac_xof(ka, m, 448, “PKA”)
    /// ## Arguments:
    /// * pub_key: [`EdCurvePoint`] : X coordinate of public key 𝑉
    /// * d: u64: Requested security strength in bits. Can only be 224, 256, 384, or 512.
    /// ## Usage:
    /// ```
    /// ```
    #[allow(non_snake_case)]
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: u64) {
        self.d = Some(d);
        let k = bytes_to_scalar(get_random_bytes(56)).mul_mod_r(&Scalar::from(4_u64));
        let w = (*pub_key * k).to_affine();
        let Z = (ExtendedPoint::tw_generator() * k).to_affine();

        let ke_ka = kmac_xof(&w.x.to_bytes().to_vec(), &[], 448 * 2, "PK", d);
        let ke = &mut ke_ka[..ke_ka.len() / 2].to_vec();
        let ka = &mut ke_ka[ke_ka.len() / 2..].to_vec();

        let t = kmac_xof(ka, &self.msg, 448, "PKA", d);
        let c = kmac_xof(ke, &[], (self.msg.len() * 8) as u64, "PKE", d);
        xor_bytes(&mut self.msg, &c);

        self.digest = Some(t);
        self.asym_nonce = Some(Z.to_extended());
    }

    /// # Asymmetric Decryption
    /// Decrypts a [`Message`] in place under private key.
    /// Operates under Schnorr/ECDHIES principle in that shared symmetric key is
    /// derived from 𝑍.
    ///
    /// ## Assumes:
    /// * well-formed encryption
    /// * Some(Message.t)
    /// * Some(Message.z)
    ///
    /// ## Replaces:
    /// * `Message.data` with result of decryption.
    /// * `Message.op_result` with result of comparision of `Message.t` == keyed hash of decryption.
    ///
    /// ## Algorithm:
    /// * s ← KMACXOF256(pw, “”, 448, “K”); s ← 4s
    /// * W ← sZ
    /// * (ke || ka) ← KMACXOF256(W x , “”, 448 * 2, “P”)
    /// * m ← KMACXOF256(ke, “”, |c|, “PKE”) ⊕ c
    /// * t’ ← KMACXOF256(ka, m, 448, “PKA”)
    ///
    /// ## Arguments:
    /// * pw: &[u8]: password used to generate ```CurvePoint``` encryption key.
    /// * d: u64: encryption security strength in bits. Can only be 224, 256, 384, or 512.
    ///
    /// ## Usage:
    /// ```
    /// ```
    #[allow(non_snake_case)]
    fn key_decrypt(&mut self, pw: &[u8]) {
        let Z = self.asym_nonce.unwrap();
        let s: Scalar = bytes_to_scalar(kmac_xof(&pw.to_owned(), &[], 448, "SK", self.d.unwrap()))
            .mul_mod_r(&Scalar::from(4_u64));
        let Z = (Z * s).to_affine();

        let ke_ka = kmac_xof(
            &Z.x.to_bytes().to_vec(),
            &[],
            448 * 2,
            "PK",
            self.d.unwrap(),
        );
        let ke = &mut ke_ka[..ke_ka.len() / 2].to_vec();
        let ka = &mut ke_ka[ke_ka.len() / 2..].to_vec();

        let m = Box::new(kmac_xof(
            ke,
            &[],
            (self.msg.len() * 8) as u64,
            "PKE",
            self.d.unwrap(),
        ));
        xor_bytes(&mut self.msg, &m);
        let t_p = kmac_xof(ka, &self.msg, 448, "PKA", self.d.unwrap());
        self.op_result = Some(t_p == self.digest.as_deref().unwrap());
    }
}

impl Signable for Message {
    /// # Schnorr Signatures
    /// Signs a [`Message`] under passphrase pw.
    ///
    /// ## Algorithm:
    /// * `s` ← kmac_xof(pw, “”, 448, “K”); s ← 4s
    /// * `k` ← kmac_xof(s, m, 448, “N”); k ← 4k
    /// * `𝑈` ← k*𝑮;
    /// * `ℎ` ← kmac_xof(𝑈ₓ , m, 448, “T”); 𝑍 ← (𝑘 – ℎ𝑠) mod r
    ///
    /// ## Arguments:
    /// * key: &[`KeyPair`], : reference to KeyPair.
    /// * d: u64: encryption security strength in bits. Can only be 224, 256, 384, or 512.
    ///
    /// ## Assumes:
    /// * Some(key.priv_key)
    ///
    /// ## Usage
    /// ```
    /// ```
    #[allow(non_snake_case)]
    fn sign(&mut self, key: &KeyPair, d: u64) {
        self.d = Some(d);

        let s: Scalar = bytes_to_scalar(kmac_xof(&key.priv_key, &[], 448, "SK", self.d.unwrap()))
            * (Scalar::from(4_u64));

        let s_bytes = scalar_to_bytes(&s);

        let k: Scalar =
            bytes_to_scalar(kmac_xof(&s_bytes, &self.msg, 448, "N", d)) * (Scalar::from(4_u64));

        let U = ExtendedPoint::tw_generator() * k;
        let ux_bytes = U.to_affine().x.to_bytes().to_vec();
        let h = kmac_xof(&ux_bytes, &self.msg, 448, "T", d);
        let h_big = bytes_to_scalar(h.clone());
        //(a % b + b) % b
        let z = k - (h_big.mul_mod_r(&s));
        self.sig = Some(Signature { h, z })
    }
    /// # Signature Verification
    /// Verifies a [`Signature`] (h, 𝑍) for a byte array m under the (Schnorr/
    /// ECDHIES) public key 𝑉.
    /// ## Algorithm:
    /// * 𝑈 ← 𝑍*𝑮 + h𝑉
    /// ## Arguments:
    /// * sig: &[`Signature`]: Pointer to a signature object (h, 𝑍)
    /// * pubKey: CurvePoint key 𝑉 used to sign message m
    /// * message: Vec<u8> of message to verify
    /// ## Assumes:
    /// * Some(key.pub_key)
    /// * Some([`Message`].sig)
    /// ## Usage
    /// ```
    /// ```
    #[allow(non_snake_case)]
    fn verify(&mut self, pub_key: &ExtendedPoint) {
        let mut U = ExtendedPoint::tw_generator() * self.sig.clone().unwrap().z;
        let hv = *pub_key * bytes_to_scalar(self.sig.clone().unwrap().h);
        U = U + (hv);
        let h_p = kmac_xof(
            &U.to_affine().x.to_bytes().to_vec(),
            &self.msg,
            448,
            "T",
            self.d.unwrap(),
        );
        self.op_result = Some(h_p == self.sig.clone().unwrap().h)
    }
}

impl AesEncryptable for Message {
    /// # Symmetric Encryption using AES in CBC Mode
    /// Encrypts a [`Message`] using the AES algorithm in CBC (Cipher Block Chaining) mode.
    /// For more information refer to: NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of encryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// * `Message.sym_nonce` with the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Random(16)
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * C1 = encrypt_block(P1 ⊕ IV)
    /// * Cj = encrypt_block(Pj ⊕ Cj-1) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &Vec<u8>`: symmetric encryption key.
    /// ## Usage:
    /// ```
    /// use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    /// use capycrypt::{Message, AesEncryptable};
    /// // Get a random 16-byte key
    /// let key = get_random_bytes(16);
    /// // Initialize the Message with some plaintext data
    /// let mut input = Message::new(get_random_bytes(5242880));
    /// // Encrypt the Message using AES in CBC mode
    /// input.aes_encrypt_cbc(&key);
    /// // Decrypt the Message (need the same key)
    /// input.aes_decrypt_cbc(&key);
    /// // Verify operation success
    /// assert!(input.op_result.unwrap());
    /// ```
    fn aes_encrypt_cbc(&mut self, key: &[u8]) {
        let iv = get_random_bytes(16);
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", 256);
        let ke = &ke_ka[..key.len()].to_vec(); // Encryption Key
        let ka = &ke_ka[key.len()..].to_vec(); // Authentication Key

        self.digest = Some(kmac_xof(ka, &self.msg, 512, "AES", 256));
        self.sym_nonce = Some(iv.clone());

        let key_schedule = AES::new(ke);

        apply_pcks7_padding(&mut self.msg);

        for block_index in (0..self.msg.len()).step_by(16) {
            xor_blocks(&mut self.msg, self.sym_nonce.as_mut().unwrap(), block_index);
            AES::encrypt_block(&mut self.msg, block_index, &key_schedule.round_key);
            *self.sym_nonce.as_mut().unwrap() = self.msg[block_index..block_index + 16].to_vec();
        }

        self.sym_nonce = Some(iv);
    }

    /// # Symmetric Decryption using AES in CBC Mode
    /// Decrypts a [`Message`] using the AES algorithm in CBC (Cipher Block Chaining) mode.
    /// For more information refer to: NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of decryption.
    /// * `Message.op_result` with the result of verification against the keyed hash.
    /// * `Message.sym_nonce` is used as the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Symmetric nonce (IV)
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * P1 = decrypt_block(C1) ⊕ IV
    /// * Pj = decrypt_block(Cj) ⊕ Cj-1 for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &Vec<u8>`: symmetric encryption key.
    /// ## Usage:
    /// ```
    /// use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    /// use capycrypt::{Message, AesEncryptable};
    /// // Get a random 16-byte key
    /// let key = get_random_bytes(16);
    /// // Initialize the Message with some ciphertext data
    /// let mut input = Message::new(get_random_bytes(5242880));
    /// // Encrypt the Message using AES in CBC mode
    /// input.aes_encrypt_cbc(&key);
    /// // Decrypt the Message (using the same key)
    /// input.aes_decrypt_cbc(&key);
    /// // Verify operation success
    /// assert!(input.op_result.unwrap());
    /// ```
    fn aes_decrypt_cbc(&mut self, key: &[u8]) {
        let mut iv = self.sym_nonce.clone().unwrap();
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let ke_ka = kmac_xof(&ke_ka, &[], 512, "AES", 256);
        let ke = &ke_ka[..key.len()].to_vec(); // Encryption Key
        let ka = &ke_ka[key.len()..].to_vec(); // Authentication Key

        let key_schedule = AES::new(ke);

        for block_index in (0..self.msg.len()).step_by(16) {
            let temp = self.msg[block_index..block_index + 16].to_vec();
            AES::decrypt_block(&mut self.msg, block_index, &key_schedule.round_key);
            xor_blocks(&mut self.msg, &iv, block_index);
            iv = temp;
        }

        remove_pcks7_padding(&mut self.msg);

        let ver = &kmac_xof(ka, &self.msg, 512, "AES", 256);
        self.op_result = Some(self.digest.as_mut().unwrap() == ver);
    }
}
