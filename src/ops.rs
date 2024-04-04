//! The main components of the cryptosystem are defined here
//! as trait implementations on specific types. The types and
//! their traits are defined in lib.rs. The arguments to all
//! operations mirror the notation from NIST FIPS 202 wherever
//! possible.
//! The Message type contains a data field. All operations are
//! performed IN PLACE.
use crate::{
    aes::aes_functions::{apply_pcks7_padding, remove_pcks7_padding, xor_blocks, AES},
    sha3::{
        aux_functions::{
            byte_utils::{
                bytes_to_scalar, get_date_and_time_as_string, get_random_bytes, scalar_to_bytes,
                xor_bytes,
            },
            nist_800_185::{byte_pad, encode_string, right_encode},
        },
        sponge::{absorb, squeeze},
    },
    AesEncryptable, BitLength, Capacity, Hashable, KeyEncryptable, KeyPair, Message,
    OperationError, OutputLength, Rate, SecParam, Signable, Signature, SpongeEncryptable,
    RATE_IN_BYTES,
};
use rayon::prelude::*;
use tiny_ed448_goldilocks::curve::{extended_edwards::ExtendedPoint, field::scalar::Scalar};

/// # SHA3-Keccak
/// ref NIST FIPS 202.
/// ## Arguments:
/// * `n: &mut Vec<u8>`: reference to message to be hashed.
/// * `d: usize`: requested output length and security strength
/// ## Returns:
/// * `return  -> Vec<u8>`: SHA3-d message digest
pub(crate) fn shake(
    n: &mut Vec<u8>,
    d: &dyn BitLength,
    buf: &mut [u8],
) -> Result<(), OperationError> {
    let bytes_to_pad = RATE_IN_BYTES - n.len() % RATE_IN_BYTES;
    match bytes_to_pad {
        1 => n.extend_from_slice(&[0x86]), // delim suffix
        _ => n.extend_from_slice(&[0x06]), // delim suffix
    }
    let c = Capacity::from_bit_length(d.bit_length());
    squeeze(&mut absorb(n, &c), d, Rate::from(&c), buf);
    Ok(())
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
/// * SHA3XOF hash of length `l` of input message `x`
/// ## Remark:
/// We can't enumerate `l` here because we need to be able to produce an arbitrary
/// length output and there is no possible way to know this value in advance.
/// The only constraint on `l` from NIST is that it is a value less than
/// the absurdly large 2^{2040}.
pub(crate) fn cshake(
    x: &[u8],
    l: usize,
    n: &str,
    s: &str,
    d: &SecParam,
    buf: &mut [u8],
) -> Result<(), OperationError> {
    d.validate()?;

    let mut encoded_n = encode_string(n.as_bytes());
    encoded_n.extend_from_slice(&encode_string(s.as_bytes()));

    let bytepad_w = d.bytepad_value();

    let mut out = byte_pad(&mut encoded_n, bytepad_w);
    out.extend_from_slice(x);
    out.push(0x04);

    let length = OutputLength::try_from(l)?;

    if n.is_empty() && s.is_empty() {
        shake(&mut out, &length, buf)?;
    }

    squeeze(&mut absorb(&mut out, d), &length, Rate::from(d), buf);
    Ok(())
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
pub(crate) fn kmac_xof(k: &[u8], x: &[u8], l: usize, s: &str, d: &SecParam, buf: &mut [u8]) {
    let mut encode_k = encode_string(k);
    let bytepad_w = d.bytepad_value();
    let mut bp = byte_pad(&mut encode_k, bytepad_w);

    // Extend bp with contents of x and right_encode(0)
    bp.extend_from_slice(x);
    bp.extend_from_slice(&right_encode(0)); // SP 800-185 4.3.1 KMAC with Arbitrary-Length Output

    let _ = cshake(&bp, l, "KMAC", s, d, buf);
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
    /// use capycrypt::{Hashable, Message, SecParam};
    /// // Hash the empty string
    /// let mut data = Message::new(vec![]);
    /// // Obtained from echo -n "" | openssl dgst -sha3-256
    /// let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    /// // Compute a SHA3 digest with 128 bits of security
    /// data.compute_hash_sha3(&SecParam::D256);
    /// // Verify successful operation
    /// data.op_result.expect("Hashing a message encountered an error");
    /// ```
    fn compute_hash_sha3(&mut self, d: &SecParam, buf: &mut [u8]) {
        let _ = shake(&mut self.msg, d, buf);
        dbg!(&buf);
        self.digest = buf.to_vec();
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
    /// use capycrypt::{Hashable, Message, SecParam::{D512}};
    /// let mut pw = "test".as_bytes().to_vec();
    /// let mut data = Message::new(vec![]);
    /// let expected = "0f9b5dcd47dc08e08a173bbe9a57b1a65784e318cf93cccb7f1f79f186ee1caeff11b12f8ca3a39db82a63f4ca0b65836f5261ee64644ce5a88456d3d30efbed";
    /// data.compute_tagged_hash(&mut pw, &"", &D512);
    /// // Verify successful operation
    /// data.op_result.expect("Computing an Authentication Tag encountered an error");
    /// ```
    fn compute_tagged_hash(&mut self, pw: &[u8], s: &str, d: &SecParam) {
        self.digest = vec![0_u8; d.bit_length() /8];
        kmac_xof(pw, &self.msg, d.bit_length(), s, d, &mut self.digest);
    }
}

impl SpongeEncryptable for Message {
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
    ///     SpongeEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}},
    ///     SecParam::D512,
    /// };
    /// use capycrypt::SecParam;
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.sha3_encrypt(&pw, &D512);
    /// // Decrypt the data
    /// msg.sha3_decrypt(&pw);
    /// // Verify successful operation
    /// assert!(msg.sha3_decrypt(&pw).is_ok(), "Decryption Failure");
    /// ```
    fn sha3_encrypt(&mut self, pw: &[u8], d: &SecParam) {
        self.d = *d;
        let z = get_random_bytes(512);

        let mut ke_ka = z.clone();
        ke_ka.extend_from_slice(pw);

        let mut keka = vec![0_u8; 1024 / 8];
        kmac_xof(&ke_ka, &[], 1024, "S", d, &mut keka);
        let (ke, ka) = keka.split_at(64);

        let mut t = vec![0_u8; 512 / 8];
        kmac_xof(ka, &self.msg, 512, "SKA", d, &mut t);
        self.digest = t;

        let mut key_stream = vec![0_u8; self.msg.len()];
        kmac_xof(ke, &[], self.msg.len() * 8, "SKE", d, &mut key_stream);
        xor_bytes(&mut self.msg, &key_stream);

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
    ///     SpongeEncryptable,
    ///     sha3::{aux_functions::{byte_utils::{get_random_bytes}}},
    ///     SecParam::D512,
    /// };
    /// use capycrypt::SecParam;
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Encrypt the data with 512 bits of security
    /// msg.sha3_encrypt(&pw, &D512);
    /// // Decrypt the data
    /// msg.sha3_decrypt(&pw);
    /// // Verify successful operation
    /// assert!(msg.sha3_decrypt(&pw).is_ok(), "Decryption Failure");
    /// ```
    fn sha3_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError> {
        let d = self.d;

        let mut z_pw = self
            .sym_nonce
            .as_ref()
            .ok_or(OperationError::SymNonceNotSet)?
            .clone();
        z_pw.extend_from_slice(pw);

        let mut keka = vec![0_u8; 1024 /8];
        kmac_xof(&z_pw, &[], 1024, "S", &d, &mut keka);
        let (ke, ka) = keka.split_at(64);

        let mut key_stream = vec![0_u8; self.msg.len()];
        kmac_xof(ke, &[], self.msg.len() * 8, "SKE", &d, &mut key_stream);

        xor_bytes(&mut self.msg, &key_stream);

        let mut t_p = vec![0_u8; 512 / 8];
        kmac_xof(ka, &self.msg, 512, "SKA", &d, &mut t_p);

        self.op_result = if self.digest == t_p {
            Ok(())
        } else {
            // revert back to the encrypted message
            xor_bytes(&mut self.msg, &key_stream);

            Err(OperationError::SHA3DecryptionFailure)
        };

        Ok(())
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
    /// use capycrypt::{
    ///     KeyEncryptable,
    ///     KeyPair,
    ///     Message,
    ///     sha3::aux_functions::byte_utils::get_random_bytes,
    ///     SecParam,
    /// };
    ///
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Create a new private/public keypair
    /// let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), &SecParam::D512).expect("Failed to create key pair");
    ///
    /// // Encrypt the message
    /// msg.key_encrypt(&key_pair.pub_key, &SecParam::D512);
    //  Decrypt the message
    /// msg.key_decrypt(&key_pair.priv_key);
    /// // Verify successful operation
    /// msg.op_result.expect("Asymmetric decryption failed");    
    /// ```
    #[allow(non_snake_case)]
    pub fn new(pw: &[u8], owner: String, d: &SecParam) -> Result<KeyPair, OperationError> {
        let mut data = vec![0_u8; 448 / 8];
        kmac_xof(pw, &[], 448, "SK", d, &mut data);
        let s: Scalar = bytes_to_scalar(data).mul_mod(&Scalar::from(4_u64));
        let V = ExtendedPoint::generator() * s;
        Ok(KeyPair {
            owner,
            pub_key: V,
            priv_key: pw.to_vec(),
            date_created: get_date_and_time_as_string(),
        })
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
    /// use capycrypt::{
    ///     KeyEncryptable,
    ///     KeyPair,
    ///     Message,
    ///     sha3::aux_functions::byte_utils::get_random_bytes,
    ///     SecParam,
    /// };
    ///
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Create a new private/public keypair
    /// let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), &SecParam::D512).expect("Failed to create key pair");
    ///
    /// // Encrypt the message
    /// msg.key_encrypt(&key_pair.pub_key, &SecParam::D512);
    //  Decrypt the message
    /// msg.key_decrypt(&key_pair.priv_key);
    /// // Verify successful operation
    /// msg.op_result.expect("Asymmetric decryption failed");    
    /// ```
    #[allow(non_snake_case)]
    fn key_encrypt(&mut self, pub_key: &ExtendedPoint, d: &SecParam) -> Result<(), OperationError> {
        self.d = *d;
        let k = bytes_to_scalar(get_random_bytes(56)).mul_mod(&Scalar::from(4_u64));
        let w = (*pub_key * k).to_affine();
        let Z = (ExtendedPoint::generator() * k).to_affine();

        let mut ke_ka = vec![0_u8; (448 * 2) / 8];
        kmac_xof(&w.x.to_bytes(), &[], 448 * 2, "PK", d, &mut ke_ka);
        let (ke, ka) = ke_ka.split_at(ke_ka.len() / 2);

        let mut t = vec![0_u8; 448 / 8];
        kmac_xof(ka, &self.msg, 448, "PKA", d, &mut t);

        let mut key_stream = vec![0_u8; self.msg.len()];
        kmac_xof(ke, &[], self.msg.len() * 8, "PKE", d, &mut key_stream);
        xor_bytes(&mut self.msg, &key_stream);

        self.digest = t;
        self.asym_nonce = Some(Z.to_extended());
        Ok(())
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
    /// use capycrypt::{
    ///     KeyEncryptable,
    ///     KeyPair,
    ///     Message,
    ///     sha3::aux_functions::byte_utils::get_random_bytes,
    ///     SecParam,
    /// };
    ///
    /// // Get 5mb random data
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Create a new private/public keypair
    /// let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), &SecParam::D512).expect("Failed to create key pair");
    ///
    /// // Encrypt the message
    /// msg.key_encrypt(&key_pair.pub_key, &SecParam::D512);
    //  Decrypt the message
    /// msg.key_decrypt(&key_pair.priv_key);
    /// // Verify successful operation
    /// msg.op_result.expect("Asymmetric decryption failed");    
    /// ```
    #[allow(non_snake_case)]
    fn key_decrypt(&mut self, pw: &[u8]) -> Result<(), OperationError> {
        let Z = self.asym_nonce.ok_or(OperationError::SymNonceNotSet)?;
        let d = self.d;

        let mut s_bytes = vec![0_u8; 448 / 8];
        kmac_xof(pw, &[], 448, "SK", &d, &mut s_bytes);
        let s = bytes_to_scalar(s_bytes).mul_mod(&Scalar::from(4_u64));
        let Z = (Z * s).to_affine();

        let mut ke_ka = vec![0_u8; (448 * 2) / 8];
        kmac_xof(&Z.x.to_bytes(), &[], 448 * 2, "PK", &d, &mut ke_ka);
        let (ke, ka) = ke_ka.split_at(ke_ka.len() / 2);

        let mut key_stream = vec![0_u8; self.msg.len()];
        kmac_xof(ke, &[], self.msg.len() * 8, "PKE", &d, &mut key_stream);
        xor_bytes(&mut self.msg, &key_stream);

        let mut t_p = vec![0_u8; 448 / 8];
        kmac_xof(ka, &self.msg, 448, "PKA", &d, &mut t_p);

        self.op_result = if self.digest == t_p {
            Ok(())
        } else {
            // revert back to the encrypted message
            xor_bytes(&mut self.msg, &key_stream);

            Err(OperationError::KeyDecryptionError)
        };

        Ok(())
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
    /// use capycrypt::{
    ///     Signable,
    ///     KeyPair,
    ///     Message,
    ///     sha3::aux_functions::byte_utils::get_random_bytes,
    ///     SecParam,
    /// };
    /// // Get random 5mb
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Generate a signing keypair
    /// let key_pair = KeyPair::new(&pw, "test key".to_string(), &SecParam::D512).expect("Failed to generate Key Pair");
    /// // Sign with 256 bits of security
    /// msg.sign(&key_pair, &SecParam::D512);
    /// // Verify signature
    /// msg.verify(&key_pair.pub_key);
    /// // Assert correctness using map
    /// msg.op_result.expect("Signature verification failed");    
    /// ```
    #[allow(non_snake_case)]
    fn sign(&mut self, key: &KeyPair, d: &SecParam) -> Result<(), OperationError> {
        let mut s_bytes = vec![0_u8; 448 / 8];
        kmac_xof(&key.priv_key, &[], 448, "SK", d, &mut s_bytes);
        let s = bytes_to_scalar(s_bytes).mul_mod(&Scalar::from(4_u64));
        let s_bytes = scalar_to_bytes(&s);

        let mut k_bytes = vec![0_u8; 448 / 8];
        kmac_xof(&s_bytes, &self.msg, 448, "N", d, &mut k_bytes);
        let k = bytes_to_scalar(k_bytes) * Scalar::from(4_u64);

        let U = ExtendedPoint::generator() * k;
        let ux_bytes = U.to_affine().x.to_bytes();

        let mut h = vec![0_u8; 448 / 8];
        kmac_xof(&ux_bytes, &self.msg, 448, "T", d, &mut h);
        let h_big = bytes_to_scalar(h.clone());

        let z = k - h_big.mul_mod(&s);
        self.sig = Some(Signature { h, z });
        self.d = *d;
        Ok(())
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
    /// use capycrypt::{
    ///     Signable,
    ///     KeyPair,
    ///     Message,
    ///     sha3::aux_functions::byte_utils::get_random_bytes,
    ///     SecParam,
    /// };
    /// // Get random 5mb
    /// let mut msg = Message::new(get_random_bytes(5242880));
    /// // Get a random password
    /// let pw = get_random_bytes(64);
    /// // Generate a signing keypair
    /// let key_pair = KeyPair::new(&pw, "test key".to_string(), &SecParam::D512).expect("Failed to generate Key Pair");
    /// // Sign with 256 bits of security
    /// msg.sign(&key_pair, &SecParam::D512);
    /// // Verify signature
    /// msg.verify(&key_pair.pub_key);
    /// // Assert correctness using map
    /// msg.op_result.expect("Signature verification failed");    
    /// ```
    #[allow(non_snake_case)]
    fn verify(&mut self, pub_key: &ExtendedPoint) -> Result<(), OperationError> {
        let sig = self.sig.as_ref().ok_or(OperationError::SignatureNotSet)?;
        let d = self.d;

        let h_scalar = bytes_to_scalar(sig.h.clone());
        let U = ExtendedPoint::generator() * sig.z + (*pub_key * h_scalar);

        let mut h_p = vec![0_u8; 448 / 8];
        kmac_xof(
            &U.to_affine().x.to_bytes(),
            &self.msg,
            448,
            "T",
            &d,
            &mut h_p,
        );

        self.op_result = if h_p == sig.h {
            Ok(())
        } else {
            Err(OperationError::SignatureVerificationFailure)
        };
        Ok(())
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
    /// // Verify successful operation
    /// input.op_result.expect("AES decryption in CBC Mode encountered an error");
    /// ```
    fn aes_encrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = get_random_bytes(16);
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let mut key_stream = vec![0_u8; 512 / 8];
        kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256, &mut key_stream);
        let ke = &key_stream[..key.len()].to_vec(); // Encryption Key
        let ka = &key_stream[key.len()..].to_vec(); // Authentication Key

        self.digest = vec![0_u8; 512 / 8];
        kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256, &mut self.digest);
        self.sym_nonce = Some(iv.clone());

        let key_schedule = AES::new(ke);

        apply_pcks7_padding(&mut self.msg);

        for block_index in (0..self.msg.len()).step_by(16) {
            xor_blocks(
                &mut self.msg[block_index..],
                self.sym_nonce.as_mut().unwrap(),
            );
            AES::encrypt_block(&mut self.msg, block_index, &key_schedule.round_key);
            *self.sym_nonce.as_mut().unwrap() = self.msg[block_index..block_index + 16].to_vec();
        }

        self.sym_nonce = Some(iv);
        Ok(())
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
    /// // Verify successful operation
    /// input.op_result.expect("AES decryption in CBC Mode encountered an error");
    /// ```
    fn aes_decrypt_cbc(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = self.sym_nonce.clone().unwrap();
        let mut ke_ka = iv.clone();
        ke_ka.append(&mut key.to_owned());
        let mut key_stream = vec![0_u8; 512 / 8];
        kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256, &mut key_stream);
        let ke = &key_stream[..key.len()].to_vec(); // Encryption Key
        let ka = &key_stream[key.len()..].to_vec(); // Authentication Key

        let key_schedule = AES::new(ke);

        let msg_copy = self.msg.clone();

        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let block_index = i * 16;
                let xor_block = if block_index >= 16 {
                    &msg_copy[block_index - 16..block_index]
                } else {
                    &iv // Use IV for the first block
                };
                // Decrypt the block in-place without using the output
                AES::decrypt_block(block, 0, &key_schedule.round_key);
                // XOR the decrypted block with the previous ciphertext block
                xor_blocks(block, xor_block);
            });

        remove_pcks7_padding(&mut self.msg);

        let mut ver = vec![0_u8; 512 / 8];
        kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256, &mut ver);
        // self.op_result = match self.digest {
        //     Ok(_) if ver == *digest => Ok(()),
        //     Ok(_) => Err(OperationError::OperationResultNotSet),
        //     Err(_) => Err(OperationError::SignatureVerificationFailure),
        // };
        Ok(())
    }

    /// # Symmetric Encryption using AES in CTR Mode
    /// Encrypts a [`Message`] using the AES algorithm in CTR (Counter) mode.
    /// For more information, refer to NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of encryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// * `Message.sym_nonce` with the initialization vector (IV).
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Random(12)
    /// * CTR ← u32 counter starting at 0
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * C1 = P1 ⊕ encrypt_block(IV || CTR1)
    /// * Cj = Pj ⊕ encrypt_block(IV || CTRj) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &[u8]`: symmetric encryption key.
    /// ## Usage:
    /// ```
    /// use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    /// use capycrypt::{Message, AesEncryptable};
    /// // Get a random 16-byte key
    /// let key = get_random_bytes(16);
    /// // Initialize the Message with some plaintext data
    /// let mut input = Message::new(get_random_bytes(5242880));
    /// // Encrypt the Message using AES in CTR mode
    /// input.aes_encrypt_ctr(&key);
    /// // Decrypt the Message (using the same key)
    /// input.aes_decrypt_ctr(&key);
    /// // Verify successful operation
    /// input.op_result.expect("AES Decryption in CTR Mode encountered an error");
    /// ```
    fn aes_encrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = get_random_bytes(12);
        let counter = 0u32;
        let counter_bytes = counter.to_be_bytes();

        let mut ke_ka = iv.clone();
        ke_ka.extend_from_slice(&counter_bytes);
        ke_ka.extend_from_slice(key);
        let mut key_stream = vec![0_u8; 512 / 8];
        kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256, &mut key_stream);

        let (ke, ka) = key_stream.split_at(key.len());

        self.sym_nonce = Some(iv.clone());

        self.digest = vec![0_u8; 512 / 8];
        kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256, &mut self.digest);

        let key_schedule = AES::new(ke);

        // Parallelize encryption for each block
        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let mut temp = iv.clone();
                let counter = i as u32;
                temp.extend_from_slice(&counter.to_be_bytes());

                AES::encrypt_block(&mut temp, 0, &key_schedule.round_key);

                xor_blocks(block, &temp);
            });

        Ok(())
    }
    /// # Symmetric Decryption using AES in CTR Mode
    /// Decrypts a [`Message`] using the AES algorithm in CTR (Counter) mode.
    /// For more information, refer to NIST Special Publication 800-38A.
    /// ## Replaces:
    /// * `Message.data` with the result of decryption.
    /// * `Message.digest` with the keyed hash of plaintext.
    /// SECURITY NOTE: ciphertext length == plaintext length
    /// ## Algorithm:
    /// * iv ← Message.sym_nonce
    /// * CTR ← u32 counter starting at 0
    /// * (ke || ka) ← kmac_xof(iv || key, “”, 512, “AES”)
    /// * P1 = C1 ⊕ encrypt_block(IV || CTR1)
    /// * Pj = Cj ⊕ encrypt_block(IV || CTRj) for j = 2 … n
    /// Here:
    /// - P: Represents plaintext blocks.
    /// - C: Represents ciphertext blocks.
    /// ## Arguments:
    /// * `key: &[u8]`: symmetric encryption key.
    /// ## Usage:
    /// ```
    /// use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    /// use capycrypt::{Message, AesEncryptable};
    /// // Get a random 16-byte key
    /// let key = get_random_bytes(16);
    /// // Initialize the Message with some ciphertext data
    /// let mut input = Message::new(get_random_bytes(5242880));
    /// // Encrypt the Message using AES in CTR mode
    /// input.aes_encrypt_ctr(&key);
    /// // Decrypt the Message using AES in CTR mode
    /// input.aes_decrypt_ctr(&key);
    /// // Verify successful operation
    /// input.op_result.expect("AES decryption in CTR Mode encountered an error");
    /// ```
    fn aes_decrypt_ctr(&mut self, key: &[u8]) -> Result<(), OperationError> {
        let iv = self
            .sym_nonce
            .clone()
            .ok_or(OperationError::SymNonceNotSet)?;
        let counter = 0u32;
        let counter_bytes = counter.to_be_bytes();

        let mut ke_ka = iv.clone();
        ke_ka.extend_from_slice(&counter_bytes);
        ke_ka.extend_from_slice(key);
        let mut key_stream = vec![0_u8; 512 / 8];
        kmac_xof(&ke_ka, &[], 512, "AES", &SecParam::D256, &mut key_stream);

        let (ke, ka) = ke_ka.split_at(key.len());

        let key_schedule = AES::new(ke);

        // Parallelize decryption for each block
        self.msg
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(i, block)| {
                let mut temp = iv.clone();
                let counter = i as u32;
                temp.extend_from_slice(&counter.to_be_bytes());

                AES::encrypt_block(&mut temp, 0, &key_schedule.round_key);

                xor_blocks(block, &temp);
            });
        let mut ver = vec![0_u8; 512 * 8];
        kmac_xof(ka, &self.msg, 512, "AES", &SecParam::D256, &mut ver);
        // self.op_result = if let digest = &self.digest {
        //     if digest == &ver {
        //         Ok(())
        //     } else {
        //         Err(OperationError::AESCTRDecryptionFailure)
        //     }
        // } else {
        //     Err(OperationError::DigestNotSet)
        // };
        Ok(())
    }
}

///
/// TESTS
///
#[cfg(test)]
mod cshake_tests {
    use crate::{ops::cshake, SecParam, NIST_DATA_SPONGE_INIT};

    #[test]
    fn test_cshake_256() {
        let mut data = NIST_DATA_SPONGE_INIT;

        let n = "";
        let s = "Email Signature";
        let mut buf = [0_u8; 32];
        let _ = cshake(&mut data, 256, n, s, &SecParam::D256, &mut buf);
        let expected: [u8; 32] = [
            0xc5, 0x22, 0x1d, 0x50, 0xe4, 0xf8, 0x22, 0xd9, 0x6a, 0x2e, 0x88, 0x81, 0xa9, 0x61,
            0x42, 0x0f, 0x29, 0x4b, 0x7b, 0x24, 0xfe, 0x3d, 0x20, 0x94, 0xba, 0xed, 0x2c, 0x65,
            0x24, 0xcc, 0x16, 0x6b,
        ];
        assert_eq!(expected.to_vec(), buf)
    }

    #[test]
    fn test_cshake_512() {
        let mut data = NIST_DATA_SPONGE_INIT;
        let n = "";
        let s = "Email Signature";
        let mut buf = [0_u8; 64];
        let _ = cshake(&mut data, 512, n, s, &SecParam::D512, &mut buf);

        let expected: [u8; 64] = [
            0x07, 0xdc, 0x27, 0xb1, 0x1e, 0x51, 0xfb, 0xac, 0x75, 0xbc, 0x7b, 0x3c, 0x1d, 0x98,
            0x3e, 0x8b, 0x4b, 0x85, 0xfb, 0x1d, 0xef, 0xaf, 0x21, 0x89, 0x12, 0xac, 0x86, 0x43,
            0x02, 0x73, 0x09, 0x17, 0x27, 0xf4, 0x2b, 0x17, 0xed, 0x1d, 0xf6, 0x3e, 0x8e, 0xc1,
            0x18, 0xf0, 0x4b, 0x23, 0x63, 0x3c, 0x1d, 0xfb, 0x15, 0x74, 0xc8, 0xfb, 0x55, 0xcb,
            0x45, 0xda, 0x8e, 0x25, 0xaf, 0xb0, 0x92, 0xbb,
        ];
        assert_eq!(expected.to_vec(), buf)
    }
}

#[cfg(test)]
mod kmac_tests {
    use crate::{ops::kmac_xof, SecParam, NIST_DATA_SPONGE_INIT};
    #[test]
    fn test_kmac_256() {
        let key_str: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];

        let s_str = "My Tagged Application";
        let key_bytes = key_str;
        let mut data = hex::decode("00010203").unwrap();
        let mut res = vec![0_u8; 64 / 8];
        kmac_xof(
            key_bytes.as_ref(),
            &mut data,
            64,
            s_str,
            &SecParam::D512,
            &mut res,
        );
        let expected = "1755133f1534752a";
        assert_eq!(hex::encode(res), expected)
    }

    #[test]
    fn test_kmac_512() {
        let key_str: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];
        let s_str = "My Tagged Application";

        let key_bytes = key_str;
        let mut data = NIST_DATA_SPONGE_INIT;
        let mut res = vec![0_u8; 512 / 8];
        kmac_xof(
            key_bytes.as_ref(),
            &mut data,
            512,
            s_str,
            &SecParam::D512,
            &mut res,
        );
        let expected: [u8; 64] = [
            0xd5, 0xbe, 0x73, 0x1c, 0x95, 0x4e, 0xd7, 0x73, 0x28, 0x46, 0xbb, 0x59, 0xdb, 0xe3,
            0xa8, 0xe3, 0x0f, 0x83, 0xe7, 0x7a, 0x4b, 0xff, 0x44, 0x59, 0xf2, 0xf1, 0xc2, 0xb4,
            0xec, 0xeb, 0xb8, 0xce, 0x67, 0xba, 0x01, 0xc6, 0x2e, 0x8a, 0xb8, 0x57, 0x8d, 0x2d,
            0x49, 0x9b, 0xd1, 0xbb, 0x27, 0x67, 0x68, 0x78, 0x11, 0x90, 0x02, 0x0a, 0x30, 0x6a,
            0x97, 0xde, 0x28, 0x1d, 0xcc, 0x30, 0x30, 0x5d,
        ];
        assert_eq!(res, expected)
    }
}

#[cfg(test)]
mod decryption_test {
    // Ensure to test if there are if & else cases: write two tests for each if and else case
    use crate::{
        sha3::aux_functions::byte_utils::get_random_bytes, KeyEncryptable, KeyPair, Message,
        SecParam::D512, SpongeEncryptable,
    };
    #[test]
    /// Testing a security parameters whether the failed decryption preserves
    /// the original encrypted text. If an encrypted text is decrypted with a wrong password,
    /// then the original encrypted message should remain the same.
    ///
    /// Note: Message were cloned for the test purposes, but in a production setting,
    /// clone() will not be used, as the operation is done in memory.
    /// Although a single security parameter is tested,
    /// it should work on the remaining security parameters.
    fn test_sha3_decrypt_handling_bad_input() {
        let pw1 = get_random_bytes(64);
        let pw2 = get_random_bytes(64);

        // D512
        let mut new_msg = Message::new(get_random_bytes(523), D512);
        let _ = new_msg.sha3_encrypt(&pw1, &D512);
        let msg2 = new_msg.msg.clone();
        let _ = new_msg.sha3_decrypt(&pw2);

        assert_eq!(msg2, new_msg.msg);
    }

    #[test]
    /// Testing a security parameters whether the failed decryption preserves
    /// the original encrypted text. If an encrypted text is decrypted with a wrong password,
    /// then the original encrypted message should remain the same.
    ///
    /// Note: Message were cloned for the test purposes, but in a production setting,
    /// clone() will not be used, as the operation is done in memory.
    /// Although a single security parameter is tested,
    /// it should work on the remaining security parameters.
    fn test_key_decrypt_handling_bad_input() {
        let mut new_msg = Message::new(get_random_bytes(125), D512);

        // D512
        let key_pair1 = KeyPair::new(&get_random_bytes(32), "test key".to_string(), &D512).unwrap();
        let key_pair2 = KeyPair::new(&get_random_bytes(32), "test key".to_string(), &D512).unwrap();

        let _ = new_msg.key_encrypt(&key_pair1.pub_key, &D512);
        let new_msg2 = new_msg.msg.clone();
        let _ = new_msg.key_decrypt(&key_pair2.priv_key);

        assert_eq!(*new_msg.msg, *new_msg2, "Message after reverting a failed decryption does not match the original encrypted message");
    }
}

#[cfg(test)]
mod shake_tests {
    use crate::SecParam::{D256, D512};
    use crate::{Hashable, Message, SecParam};
    #[test]
    fn test_shake_224() {
        let data = Message::new(vec![], D512);
        let expected: [u8; 28] = [
            0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e,
            0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7,
        ];

        assert!(data.digest == expected.to_vec());

        let data = Message::new("test".as_bytes().to_vec(), D512);
        let expected: [u8; 28] = [
            0x37, 0x97, 0xbf, 0x0a, 0xfb, 0xbf, 0xca, 0x4a, 0x7b, 0xbb, 0xa7, 0x60, 0x2a, 0x2b,
            0x55, 0x27, 0x46, 0x87, 0x65, 0x17, 0xa7, 0xf9, 0xb7, 0xce, 0x2d, 0xb0, 0xae, 0x7b,
        ];

        assert!(data.digest == expected.to_vec());
    }

    #[test]
    fn test_shake_256() {
        let mut data = Message::new(vec![], D256);
        let expected: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        let mut buf = vec![0_u8; 32];
        data.compute_hash_sha3(&D256, &mut buf);
        assert_eq!(buf, expected.to_vec());

        // let mut data = Message::new("test".as_bytes().to_vec(), D512);
        // let expected: [u8; 32] = [
        //     0x36, 0xf0, 0x28, 0x58, 0x0b, 0xb0, 0x2c, 0xc8, 0x27, 0x2a, 0x9a, 0x02, 0x0f, 0x42,
        //     0x00, 0xe3, 0x46, 0xe2, 0x76, 0xae, 0x66, 0x4e, 0x45, 0xee, 0x80, 0x74, 0x55, 0x74,
        //     0xe2, 0xf5, 0xab, 0x80,
        // ];
        // let mut buf = vec![0_u8; 32];
        // data.compute_hash_sha3(&D512, &mut buf);
        // assert!(buf == expected.to_vec());
    }

    #[test]
    fn test_shake_384() {
        let data = Message::new(vec![], D512);
        let expected: [u8; 48] = [
            0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c,
            0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb,
            0xee, 0x98, 0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b,
            0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
        ];

        assert!(data.digest == expected.to_vec());

        let data = Message::new("test".as_bytes().to_vec(), D512);
        let expected: [u8; 48] = [
            0xe5, 0x16, 0xda, 0xbb, 0x23, 0xb6, 0xe3, 0x00, 0x26, 0x86, 0x35, 0x43, 0x28, 0x27,
            0x80, 0xa3, 0xae, 0x0d, 0xcc, 0xf0, 0x55, 0x51, 0xcf, 0x02, 0x95, 0x17, 0x8d, 0x7f,
            0xf0, 0xf1, 0xb4, 0x1e, 0xec, 0xb9, 0xdb, 0x3f, 0xf2, 0x19, 0x00, 0x7c, 0x4e, 0x09,
            0x72, 0x60, 0xd5, 0x86, 0x21, 0xbd,
        ];

        assert!(data.digest == expected.to_vec());
    }

    #[test]
    fn test_shake_512() {
        let data = Message::new("test".as_bytes().to_vec(), D512);
        let expected: [u8; 64] = [
            0x9e, 0xce, 0x08, 0x6e, 0x9b, 0xac, 0x49, 0x1f, 0xac, 0x5c, 0x1d, 0x10, 0x46, 0xca,
            0x11, 0xd7, 0x37, 0xb9, 0x2a, 0x2b, 0x2e, 0xbd, 0x93, 0xf0, 0x05, 0xd7, 0xb7, 0x10,
            0x11, 0x0c, 0x0a, 0x67, 0x82, 0x88, 0x16, 0x6e, 0x7f, 0xbe, 0x79, 0x68, 0x83, 0xa4,
            0xf2, 0xe9, 0xb3, 0xca, 0x9f, 0x48, 0x4f, 0x52, 0x1d, 0x0c, 0xe4, 0x64, 0x34, 0x5c,
            0xc1, 0xae, 0xc9, 0x67, 0x79, 0x14, 0x9c, 0x14,
        ];

        assert!(data.digest == expected.to_vec());
    }

    #[test]
    fn test_compute_tagged_hash_256() {
        let s = "".to_string();
        let mut pw = "".as_bytes().to_vec();
        let mut data = Message::new(vec![], D512);
        let expected: [u8; 32] = [
            0x3f, 0x92, 0x59, 0xe8, 0x0b, 0x35, 0xe0, 0x71, 0x9c, 0x26, 0x02, 0x5f, 0x7e, 0x38,
            0xa4, 0xa3, 0x81, 0x72, 0xbf, 0x11, 0x42, 0xa6, 0xa9, 0xc1, 0x93, 0x0e, 0x50, 0xdf,
            0x03, 0x90, 0x43, 0x12,
        ];
        data.compute_tagged_hash(&mut pw, &s, &SecParam::D256);

        assert!(data.digest == expected.to_vec())
    }

    #[test]
    fn test_compute_tagged_hash_512() {
        let mut pw = "test".as_bytes().to_vec();
        let mut data = Message::new(vec![], D512);
        let expected: [u8; 64] = [
            0x0f, 0x9b, 0x5d, 0xcd, 0x47, 0xdc, 0x08, 0xe0, 0x8a, 0x17, 0x3b, 0xbe, 0x9a, 0x57,
            0xb1, 0xa6, 0x57, 0x84, 0xe3, 0x18, 0xcf, 0x93, 0xcc, 0xcb, 0x7f, 0x1f, 0x79, 0xf1,
            0x86, 0xee, 0x1c, 0xae, 0xff, 0x11, 0xb1, 0x2f, 0x8c, 0xa3, 0xa3, 0x9d, 0xb8, 0x2a,
            0x63, 0xf4, 0xca, 0x0b, 0x65, 0x83, 0x6f, 0x52, 0x61, 0xee, 0x64, 0x64, 0x4c, 0xe5,
            0xa8, 0x84, 0x56, 0xd3, 0xd3, 0x0e, 0xfb, 0xed,
        ];
        data.compute_tagged_hash(&mut pw, "", &SecParam::D512);

        assert!(data.digest == expected.to_vec());
    }
}
