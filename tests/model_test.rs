#[cfg(test)]
pub mod model_test {
    
    use cryptotool::model::shake_functions::{encrypt_with_pw, decrypt_with_pw};

    #[test]
    pub fn test_sym_enc_dec() {

        let pw = "test";
        let mut message = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();

        let cg1 = encrypt_with_pw(&mut pw.as_bytes().to_vec(), &mut message);
        
        let mut pw = "test".as_bytes().to_vec();
        let msg_str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7";
        let mut message = hex::decode(msg_str).unwrap();
        let mut cg2 = encrypt_with_pw(&mut pw, &mut message);

        assert!(cg1.z != cg2.z);
        assert!(cg1.c != cg2.c);
        assert!(cg1.t != cg2.t);
        
        let mut pw = "test".as_bytes().to_vec();
        let res = decrypt_with_pw(&mut pw, &mut cg2);
        println!("result: {:?}", res);
        println!("result: {:?}", hex::encode(cg2.c));
        // assert!(res);
        // assert!(hex::encode(cg2.c).eq(msg_str));

        




    }


}