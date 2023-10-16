#[cfg(test)]
pub mod model_tests {
    use capycrypt::curves::EdCurves::{self, E448};
    use capycrypt::curves::{ArbitraryPoint, EdCurvePoint};
    use capycrypt::ops::{Hashable, KeyEncryptable, Message, PwEncryptable, Signable};
    use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    use std::borrow::BorrowMut;
    use std::time::Instant;
    const SELECTED_CURVE: EdCurves = E448;

    #[test]
    pub fn test_sym_enc_512() {
        let pw = get_random_bytes(64);

        let mut msg = Message {
            msg: Box::new(get_random_bytes(52).to_owned()),
            digest: None,
            sym_params: None,
            ecc_params: None,
            op_result: None,
            signature: None,
        };

        // let mut message = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
        msg.encrypt_with_pw(&mut pw.clone(), 512);
        msg.decrypt_with_pw(&mut pw.clone(), 512);
        let res = msg.op_result.unwrap();
        println!("result: {:?}", res);
        assert!(res);
    }
}
//     #[test]
//     pub fn test_sym_enc_256() {
//         let pw = get_random_bytes(64);

//         let mut msg = Message {
//             data: Box::new(get_random_bytes(5242880).to_owned()),
//             sym_params: None,
//             ecc_params: None,
//             op_result: None,
//             signature: None,
//         };
//         // let mut message = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7").unwrap();
//         msg.encrypt_with_pw(&mut pw.clone(), 256);
//         msg.decrypt_with_pw(&mut pw.clone(), 256);
//         let res = msg.op_result.unwrap();
//         assert!(res);
//     }

//     #[test]
//     fn test_key_gen_enc_dec_256() {
//         //check conversion to and from bytes.
//         let pw = get_random_bytes(32);
//         let owner = "test key".to_string();
//         let mut message = Box::new(get_random_bytes(5242880).to_owned()); //5mb
//         let key_obj = gen_keypair(&mut pw.clone(), owner, 256);
//         let x = key_obj.pub_x;
//         let y = key_obj.pub_y;
//         let pub_key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
//         let mut enc = encrypt_with_key(pub_key, &mut message, 256);
//         let res = decrypt_with_key(&mut pw.clone(), enc.borrow_mut(), 256);
//         assert!(res);
//     }

//     #[test]
//     fn test_key_gen_enc_dec_512() {
//         //check conversion to and from bytes.
//         let pw = get_random_bytes(64);
//         let owner = "test key".to_string();
//         let mut message = Box::new(get_random_bytes(5242880).to_owned()); //5mb
//         let key_obj = gen_keypair(&mut pw.clone(), owner, 512);
//         let x = key_obj.pub_x;
//         let y = key_obj.pub_y;
//         let pub_key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
//         let mut enc = encrypt_with_key(pub_key, &mut message, 512);
//         let res = decrypt_with_key(&mut pw.clone(), enc.borrow_mut(), 512);
//         assert!(res);
//     }

//     #[test]
//     pub fn test_signature_512() {
//         let mut message = Box::new(get_random_bytes(5242880).to_owned());
//         let pw = get_random_bytes(64);
//         let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 512);
//         let x = key_obj.pub_x;
//         let y = key_obj.pub_y;
//         let key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
//         let sig = sign_with_key(&mut pw.clone(), &mut message, 512);
//         let res = verify_signature(&sig, key, &mut message, 512);
//         assert!(res);
//     }

//     #[test]
//     fn test_sig_timing_side_channel() {
//         for i in 0..32 {
//             let mut message = Box::new(get_random_bytes(16).to_owned());
//             let pw = get_random_bytes(1 + i);
//             let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 256);
//             let x = key_obj.pub_x;
//             let y = key_obj.pub_y;
//             let key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);

//             let now = Instant::now();
//             let _result = sign_with_key(&mut pw.clone(), &mut message, 256);
//             println!("{} needed {} micro seconds", i, now.elapsed().as_micros());
//             assert!(verify_signature(&_result, key, &mut message, 256));
//         }
//     }

//     #[test]
//     pub fn test_signature_256() {
//         let mut message = Box::new(get_random_bytes(5242880).to_owned());
//         let pw = get_random_bytes(32);
//         let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 256);
//         let x = key_obj.pub_x;
//         let y = key_obj.pub_y;
//         let key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
//         let sig = sign_with_key(&mut pw.clone(), &mut message, 256);
//         let res = verify_signature(&sig, key, &mut message, 256);
//         assert!(res);
//     }
// }
