#[cfg(test)]
pub mod model_tests {
    use capycrypt::curve::Curves;
    use capycrypt::curve::{CurvePoint, Point};
    use capycrypt::model::operations::{
        decrypt_with_key, decrypt_with_pw, encrypt_with_key, encrypt_with_pw, gen_keypair,
        sign_with_key, verify_signature,
    };
    use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    use std::borrow::BorrowMut;
    const SELECTED_CURVE: Curves = Curves::E448;

    #[test]
    pub fn test_sym_enc_512() {
        let pw = get_random_bytes(64);
        let mut message = Box::new(get_random_bytes(5242880).to_owned());
        // let mut message = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let mut cg2 = Box::new(encrypt_with_pw(&mut pw.clone(), &mut message, 512));
        let res = decrypt_with_pw(&mut pw.clone(), &mut cg2.borrow_mut(), 512);
        assert!(res);
    }

    #[test]
    pub fn test_sym_enc_256() {
        let pw = get_random_bytes(32);
        let mut message = Box::new(get_random_bytes(5242880).to_owned());
        // let mut message = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        let mut cg2 = Box::new(encrypt_with_pw(&mut pw.clone(), &mut message, 256));
        let res = decrypt_with_pw(&mut pw.clone(), &mut cg2.borrow_mut(), 256);
        assert!(res);
    }

    #[test]
    fn test_key_gen_enc_dec_256() {
        //check conversion to and from bytes.
        let pw = get_random_bytes(32);
        let owner = "test key".to_string();
        let mut message = Box::new(get_random_bytes(5242880).to_owned()); //5mb
        let key_obj = gen_keypair(&mut pw.clone(), owner, 256);
        let x = key_obj.pub_x;
        let y = key_obj.pub_y;
        let pub_key = CurvePoint::point(SELECTED_CURVE, x, y);
        let mut enc = encrypt_with_key(pub_key, &mut message, 256);
        let res = decrypt_with_key(&mut pw.clone(), enc.borrow_mut(), 256);
        assert!(res);
    }

    #[test]
    fn test_key_gen_enc_dec_512() {
        //check conversion to and from bytes.
        let pw = get_random_bytes(64);
        let owner = "test key".to_string();
        let mut message = Box::new(get_random_bytes(5242880).to_owned()); //5mb
        let key_obj = gen_keypair(&mut pw.clone(), owner, 512);
        let x = key_obj.pub_x;
        let y = key_obj.pub_y;
        let pub_key = CurvePoint::point(SELECTED_CURVE, x, y);
        let mut enc = encrypt_with_key(pub_key, &mut message, 512);
        let res = decrypt_with_key(&mut pw.clone(), enc.borrow_mut(), 512);
        assert!(res);
    }

    #[test]
    pub fn test_signature_512() {
        let mut message = Box::new(get_random_bytes(5242880).to_owned());
        let pw = get_random_bytes(64);
        let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 512);
        let x = key_obj.pub_x;
        let y = key_obj.pub_y;
        let key = CurvePoint::point(SELECTED_CURVE, x, y);
        let sig = sign_with_key(&mut pw.clone(), &mut message, 512);
        let res = verify_signature(&sig, key, &mut message, 512);
        assert!(res);
    }

    #[test]
    pub fn test_signature_256() {
        let mut message = Box::new(get_random_bytes(5242880).to_owned());
        let pw = get_random_bytes(32);
        let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 256);
        let x = key_obj.pub_x;
        let y = key_obj.pub_y;
        let key = CurvePoint::point(SELECTED_CURVE, x, y);
        let sig = sign_with_key(&mut pw.clone(), &mut message, 256);
        let res = verify_signature(&sig, key, &mut message, 256);
        assert!(res);
    }
}
