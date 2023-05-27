/// Test cases for cSHAKE and KMAC functionality. All values labeled
/// "exptected" in cshake and kmac tests are official test vectors supplied by NIST.
#[cfg(test)]
mod sponge_tests {
    use capycrypt::model::shake_functions::{compute_sha3_hash, cshake, kmac_xof};
    use capycrypt::sha3::aux_functions::nist_800_185::{byte_pad, left_encode, right_encode};
    use capycrypt::sha3::{
        aux_functions::byte_utils::get_random_bytes,
        sponge::{sponge_absorb, sponge_squeeze},
    };
    use hex::ToHex;

    #[test]
    fn test_kmac_256() {
        let key_str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let s_str = "My Tagged Application";

        let mut key_bytes = hex::decode(key_str).unwrap();
        let mut data = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();

        let res = kmac_xof(&mut key_bytes, &mut data, 256, &s_str, 256);
        let expected = "47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f";
        assert_eq!(hex::encode(res), expected)
    }

    #[test]
    fn test_kmac_512() {
        let key_str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let s_str = "My Tagged Application";

        let mut key_bytes = hex::decode(key_str).unwrap();
        let mut data = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();

        let res = kmac_xof(&mut key_bytes, &mut data, 512, &s_str, 512);
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

    // #[test]
    // #[should_panic = "Value must be either 256 or 512"]
    // fn test_cshake_invalid() {
    //     cshake(&mut vec![0], 0, "Test", "Test");
    // }

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

    #[test]
    fn test_shake() {
        //test for expected NIST values
        let mut test_bytes = "".as_bytes().to_vec();
        let res = compute_sha3_hash(&mut test_bytes).encode_hex::<String>();
        let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
        assert!(res == expected);

        let mut test_bytes = "test".as_bytes().to_vec();
        let expected = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        let res = compute_sha3_hash(&mut test_bytes).encode_hex::<String>();
        assert!(res == expected);
    }

    #[test]
    fn test_shake_run_time() {
        //test runtime of different input sizes
        let mut message = get_random_bytes(5242880).to_vec();
        let _ = hex::encode(compute_sha3_hash(&mut message));
    }
}
