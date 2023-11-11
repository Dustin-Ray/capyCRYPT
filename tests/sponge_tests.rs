use capycrypt::{Hashable, Message};
/// Test cases for cSHAKE and KMAC functionality. All values labeled
/// "exptected" in cshake and kmac tests are official test vectors supplied by NIST.
#[cfg(test)]
mod sponge_tests {
    use capycrypt::ops::{cshake, kmac_xof};
    use capycrypt::sha3::aux_functions::nist_800_185::{byte_pad, left_encode, right_encode};
    use capycrypt::sha3::sponge::{sponge_absorb, sponge_squeeze};
    use hex::ToHex;

    #[test]
    fn test_kmac_256() {
        let key_str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let s_str = "My Tagged Application";
        let key_bytes = hex::decode(key_str).unwrap();
        let mut data = hex::decode("00010203").unwrap();
        let res = kmac_xof(&key_bytes, &mut data, 64, &s_str, 512);
        let expected = "1755133f1534752a";
        assert_eq!(hex::encode(res), expected)
    }

    #[test]
    fn test_kmac_512() {
        let key_str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let s_str = "My Tagged Application";

        let key_bytes = hex::decode(key_str).unwrap();
        let mut data = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();

        let res = kmac_xof(&key_bytes, &mut data, 512, &s_str, 512);
        let expected = "d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d";
        assert_eq!(hex::encode(res), expected)
    }

    #[test]
    fn test_cshake_256() {
        let mut data = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let n = "";
        let s = "Email Signature";
        let res = cshake(&mut data, 256, n, s, 256);
        let expected =
            hex::decode("c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b")
                .unwrap();
        assert_eq!(expected, res)
    }

    #[test]
    fn test_cshake_512() {
        let mut data = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let n = "";
        let s = "Email Signature";
        let res = cshake(&mut data, 512, n, s, 512);
        let expected = hex::decode("07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb").unwrap();
        assert_eq!(expected, res)
    }

    #[test]
    fn test_bytepad() {
        let mut val = "test".as_bytes().to_vec();
        let val_len = val.len() as u32;
        let expected = [1, 4, 116, 101, 115, 116, 0, 0];
        assert_eq!(byte_pad(&mut val, val_len), expected);

        let expected = [
            1, 200, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
            44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
            66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
            88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
            125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
            142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158,
            159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
            176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
            193, 194, 195, 196, 197, 198, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let mut val = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let val_len = val.len() as u32;
        assert_eq!(byte_pad(&mut val, val_len), expected);
    }

    #[test]
    fn test_right_encode() {
        let val = 0;
        let expected = [0, 1];
        assert_eq!(right_encode(val), expected);

        let val = 0xFFFFFFFFFFFFFF;
        let expected = [8, 255, 255, 255, 255, 255, 255, 255];
        assert_eq!(right_encode(val), expected);

        let val = 10000000000;
        let expected = [6, 0, 0, 2, 84, 11];
        assert_eq!(right_encode(val), expected);

        let val = 10000000000000000000;
        let expected = [8, 199, 35, 4, 137, 232, 0, 0];
        assert_eq!(right_encode(val), expected);

        let val = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let val_len = val.len();
        let expected = [2, 0];

        let res = right_encode(val_len as u64);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_left_encode() {
        let val = 0;
        let expected = [1, 0];
        assert_eq!(left_encode(val), expected);

        let val = 0xFFFFFFFFFFFFFF;
        let expected = [7, 255, 255, 255, 255, 255, 255, 255];
        // println!("{:?}", left_encode(val));
        assert_eq!(left_encode(val), expected);

        let val = 10000000000;
        let expected = [5, 2, 84, 11, 228, 0];
        // println!("{:?}", left_encode(val));
        assert_eq!(left_encode(val), expected);

        let val = 10000000000000000000;
        let expected = [8, 138, 199, 35, 4, 137, 232, 0, 0];
        assert_eq!(left_encode(val), expected);

        let val = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let val_len = val.len();
        let expected = [1, 200];

        let res = left_encode(val_len as u64);
        // println!("{:?}", res);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_sponge() {
        let res = sponge_squeeze(
            &mut sponge_absorb(&mut "test".as_bytes().to_vec(), 256),
            512,
            136,
        );
        let s = res.encode_hex::<String>();

        let expected = "8ee1f95dfe959e1d5e8188df176516b25de2d1c5ebf8f3312a588fba9f0a23e7437379c2035a8208df6ab2b68a9327c7e42e13bdd7fc2222dd611f0f755d8808";
        assert!(s == expected)
    }
}
#[test]
fn test_shake_224() {
    let mut data = Message::new(vec![]);
    let expected = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    data.compute_sha3_hash(224);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);

    let mut data = Message::new("test".as_bytes().to_vec());
    let expected = "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b";
    data.compute_sha3_hash(224);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}

#[test]
fn test_shake_256() {
    let mut data = Message::new(vec![]);
    let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    data.compute_sha3_hash(256);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);

    let mut data = Message::new("test".as_bytes().to_vec());
    let expected = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
    data.compute_sha3_hash(256);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}

#[test]
fn test_shake_384() {
    let mut data = Message::new(vec![]);
    let expected = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    data.compute_sha3_hash(384);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);

    let mut data = Message::new("test".as_bytes().to_vec());
    let expected = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
    data.compute_sha3_hash(384);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}

#[test]
fn test_shake_512() {
    let mut data = Message::new("test".as_bytes().to_vec());
    let expected = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
    data.compute_sha3_hash(512);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}

#[test]
fn test_compute_tagged_hash_256() {
    let s = "".to_string();
    let mut pw = "".as_bytes().to_vec();
    let mut data = Message::new(vec![]);
    let expected = "3f9259e80b35e0719c26025f7e38a4a38172bf1142a6a9c1930e50df03904312";
    data.compute_tagged_hash(&mut pw, &s, 256);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}

#[test]
fn test_compute_tagged_hash_512() {
    let mut pw = "test".as_bytes().to_vec();
    let mut data = Message::new(vec![]);
    let expected = "0f9b5dcd47dc08e08a173bbe9a57b1a65784e318cf93cccb7f1f79f186ee1caeff11b12f8ca3a39db82a63f4ca0b65836f5261ee64644ce5a88456d3d30efbed";
    data.compute_tagged_hash(&mut pw, &"", 512);
    assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
}
