//! The main components of the cryptosystem are defined here
//! as trait implementations on specific types. The types and
//! their traits are defined in lib.rs. The arguments to all
//! operations mirror the notation from NIST FIPS 202 wherever
//! possible.
//! The Message type contains a data field. All operations are
//! performed IN PLACE.
use crate::{
    sha3::{
        aux_functions::nist_800_185::{byte_pad, encode_string, right_encode},
        sponge::{sponge_absorb, sponge_squeeze},
    },
    BitLength, Capacity, OperationError, OutputLength, Rate, SecParam, RATE_IN_BYTES,
};

/// # SHA3-Keccak
/// ref NIST FIPS 202.
/// ## Arguments:
/// * `n: &mut Vec<u8>`: reference to message to be hashed.
/// * `d: usize`: requested output length and security strength
/// ## Returns:
/// * `return  -> Vec<u8>`: SHA3-d message digest
pub(crate) fn shake(n: &mut Vec<u8>, d: &dyn BitLength) -> Result<Vec<u8>, OperationError> {
    let bytes_to_pad = RATE_IN_BYTES - n.len() % RATE_IN_BYTES;
    match bytes_to_pad {
        1 => n.extend_from_slice(&[0x86]), // delim suffix
        _ => n.extend_from_slice(&[0x06]), // delim suffix
    }
    let c = Capacity::from_bit_length(d.bit_length());
    Ok(sponge_squeeze(&mut sponge_absorb(n, &c), d, Rate::from(&c)))
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
    l: u64,
    n: &str,
    s: &str,
    d: &SecParam,
) -> Result<Vec<u8>, OperationError> {
    d.validate()?;

    let mut encoded_n = encode_string(n.as_bytes());
    encoded_n.extend_from_slice(&encode_string(s.as_bytes()));

    let bytepad_w = d.bytepad_value();

    let mut out = byte_pad(&mut encoded_n, bytepad_w);
    out.extend_from_slice(x);
    out.push(0x04);

    let length = OutputLength::try_from(l)?;

    if n.is_empty() && s.is_empty() {
        shake(&mut out, &length)?;
    }

    Ok(sponge_squeeze(
        &mut sponge_absorb(&mut out, d),
        &length,
        Rate::from(d),
    ))
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
pub fn kmac_xof(
    k: &[u8],
    x: &[u8],
    l: u64,
    s: &str,
    d: &SecParam,
) -> Result<Vec<u8>, OperationError> {
    let mut encode_k = encode_string(k);
    let bytepad_w = d.bytepad_value();
    let mut bp = byte_pad(&mut encode_k, bytepad_w);

    // Extend bp with contents of x and right_encode(0)
    bp.extend_from_slice(x);
    bp.extend_from_slice(&right_encode(0)); // SP 800-185 4.3.1 KMAC with Arbitrary-Length Output

    cshake(&bp, l, "KMAC", s, d)
}

/// TESTS
#[cfg(test)]
mod cshake_tests {
    use crate::{sha3::shake_functions::cshake, SecParam, NIST_DATA_SPONGE_INIT};

    #[test]
    fn test_cshake_256() {
        let data = NIST_DATA_SPONGE_INIT;

        let n = "";
        let s = "Email Signature";
        let res = cshake(&data, 256, n, s, &SecParam::D256).unwrap();
        let expected: [u8; 32] = [
            0xc5, 0x22, 0x1d, 0x50, 0xe4, 0xf8, 0x22, 0xd9, 0x6a, 0x2e, 0x88, 0x81, 0xa9, 0x61,
            0x42, 0x0f, 0x29, 0x4b, 0x7b, 0x24, 0xfe, 0x3d, 0x20, 0x94, 0xba, 0xed, 0x2c, 0x65,
            0x24, 0xcc, 0x16, 0x6b,
        ];
        assert_eq!(expected.to_vec(), res)
    }

    #[test]
    fn test_cshake_512() {
        let data = NIST_DATA_SPONGE_INIT;
        let n = "";
        let s = "Email Signature";
        let res = cshake(&data, 512, n, s, &SecParam::D512).unwrap();
        let expected: [u8; 64] = [
            0x07, 0xdc, 0x27, 0xb1, 0x1e, 0x51, 0xfb, 0xac, 0x75, 0xbc, 0x7b, 0x3c, 0x1d, 0x98,
            0x3e, 0x8b, 0x4b, 0x85, 0xfb, 0x1d, 0xef, 0xaf, 0x21, 0x89, 0x12, 0xac, 0x86, 0x43,
            0x02, 0x73, 0x09, 0x17, 0x27, 0xf4, 0x2b, 0x17, 0xed, 0x1d, 0xf6, 0x3e, 0x8e, 0xc1,
            0x18, 0xf0, 0x4b, 0x23, 0x63, 0x3c, 0x1d, 0xfb, 0x15, 0x74, 0xc8, 0xfb, 0x55, 0xcb,
            0x45, 0xda, 0x8e, 0x25, 0xaf, 0xb0, 0x92, 0xbb,
        ];
        assert_eq!(expected.to_vec(), res)
    }
}

#[cfg(test)]
mod kmac_tests {
    use crate::{kmac_xof, SecParam, NIST_DATA_SPONGE_INIT};
    #[test]
    fn test_kmac_256() {
        let key_str: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];

        let s_str = "My Tagged Application";
        let key_bytes = key_str;
        let data = hex::decode("00010203").unwrap();
        let res = kmac_xof(key_bytes.as_ref(), &data, 64, s_str, &SecParam::D512).unwrap();
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
        let data = NIST_DATA_SPONGE_INIT;
        let res = kmac_xof(key_bytes.as_ref(), &data, 512, s_str, &SecParam::D512).unwrap();
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
        let mut new_msg = Message::new(get_random_bytes(523));
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
        let mut new_msg = Message::new(get_random_bytes(125));

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
    use crate::{Hashable, Message, SecParam};

    #[test]
    fn test_shake_224() {
        let mut data = Message::new(vec![]);
        let expected: [u8; 28] = [
            0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e,
            0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D224).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));

        let mut data = Message::new("test".as_bytes().to_vec());
        let expected: [u8; 28] = [
            0x37, 0x97, 0xbf, 0x0a, 0xfb, 0xbf, 0xca, 0x4a, 0x7b, 0xbb, 0xa7, 0x60, 0x2a, 0x2b,
            0x55, 0x27, 0x46, 0x87, 0x65, 0x17, 0xa7, 0xf9, 0xb7, 0xce, 0x2d, 0xb0, 0xae, 0x7b,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D224).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }

    #[test]
    fn test_shake_256() {
        let mut data = Message::new(vec![]);
        let expected: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D256).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));

        let mut data = Message::new("test".as_bytes().to_vec());
        let expected: [u8; 32] = [
            0x36, 0xf0, 0x28, 0x58, 0x0b, 0xb0, 0x2c, 0xc8, 0x27, 0x2a, 0x9a, 0x02, 0x0f, 0x42,
            0x00, 0xe3, 0x46, 0xe2, 0x76, 0xae, 0x66, 0x4e, 0x45, 0xee, 0x80, 0x74, 0x55, 0x74,
            0xe2, 0xf5, 0xab, 0x80,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D256).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }

    #[test]
    fn test_shake_384() {
        let mut data = Message::new(vec![]);
        let expected: [u8; 48] = [
            0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c,
            0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb,
            0xee, 0x98, 0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b,
            0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D384).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));

        let mut data = Message::new("test".as_bytes().to_vec());
        let expected: [u8; 48] = [
            0xe5, 0x16, 0xda, 0xbb, 0x23, 0xb6, 0xe3, 0x00, 0x26, 0x86, 0x35, 0x43, 0x28, 0x27,
            0x80, 0xa3, 0xae, 0x0d, 0xcc, 0xf0, 0x55, 0x51, 0xcf, 0x02, 0x95, 0x17, 0x8d, 0x7f,
            0xf0, 0xf1, 0xb4, 0x1e, 0xec, 0xb9, 0xdb, 0x3f, 0xf2, 0x19, 0x00, 0x7c, 0x4e, 0x09,
            0x72, 0x60, 0xd5, 0x86, 0x21, 0xbd,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D384).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }

    #[test]
    fn test_shake_512() {
        let mut data = Message::new("test".as_bytes().to_vec());
        let expected: [u8; 64] = [
            0x9e, 0xce, 0x08, 0x6e, 0x9b, 0xac, 0x49, 0x1f, 0xac, 0x5c, 0x1d, 0x10, 0x46, 0xca,
            0x11, 0xd7, 0x37, 0xb9, 0x2a, 0x2b, 0x2e, 0xbd, 0x93, 0xf0, 0x05, 0xd7, 0xb7, 0x10,
            0x11, 0x0c, 0x0a, 0x67, 0x82, 0x88, 0x16, 0x6e, 0x7f, 0xbe, 0x79, 0x68, 0x83, 0xa4,
            0xf2, 0xe9, 0xb3, 0xca, 0x9f, 0x48, 0x4f, 0x52, 0x1d, 0x0c, 0xe4, 0x64, 0x34, 0x5c,
            0xc1, 0xae, 0xc9, 0x67, 0x79, 0x14, 0x9c, 0x14,
        ];
        assert!(data.compute_hash_sha3(&SecParam::D512).is_ok());
        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }

    #[test]
    fn test_compute_tagged_hash_256() {
        let s = "".to_string();
        let pw = "".as_bytes().to_vec();
        let mut data = Message::new(vec![]);
        let expected: [u8; 32] = [
            0x3f, 0x92, 0x59, 0xe8, 0x0b, 0x35, 0xe0, 0x71, 0x9c, 0x26, 0x02, 0x5f, 0x7e, 0x38,
            0xa4, 0xa3, 0x81, 0x72, 0xbf, 0x11, 0x42, 0xa6, 0xa9, 0xc1, 0x93, 0x0e, 0x50, 0xdf,
            0x03, 0x90, 0x43, 0x12,
        ];
        data.compute_tagged_hash(&pw, &s, &SecParam::D256);

        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }

    #[test]
    fn test_compute_tagged_hash_512() {
        let pw = "test".as_bytes().to_vec();
        let mut data = Message::new(vec![]);
        let expected: [u8; 64] = [
            0x0f, 0x9b, 0x5d, 0xcd, 0x47, 0xdc, 0x08, 0xe0, 0x8a, 0x17, 0x3b, 0xbe, 0x9a, 0x57,
            0xb1, 0xa6, 0x57, 0x84, 0xe3, 0x18, 0xcf, 0x93, 0xcc, 0xcb, 0x7f, 0x1f, 0x79, 0xf1,
            0x86, 0xee, 0x1c, 0xae, 0xff, 0x11, 0xb1, 0x2f, 0x8c, 0xa3, 0xa3, 0x9d, 0xb8, 0x2a,
            0x63, 0xf4, 0xca, 0x0b, 0x65, 0x83, 0x6f, 0x52, 0x61, 0xee, 0x64, 0x64, 0x4c, 0xe5,
            0xa8, 0x84, 0x56, 0xd3, 0xd3, 0x0e, 0xfb, 0xed,
        ];
        data.compute_tagged_hash(&pw, "", &SecParam::D512);

        assert!(data
            .digest
            .as_ref()
            .map(|digest| *digest == expected.to_vec())
            .unwrap_or(false));
    }
}
