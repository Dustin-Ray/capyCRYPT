#[cfg(test)]
pub mod ops_tests {
    use capycrypt::ops::{KeyEncryptable, Message, PwEncryptable, Signable};
    use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    use capycrypt::KeyPair;
    use std::borrow::BorrowMut;
    use std::time::Instant;

    #[test]
    pub fn test_sym_enc_512() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(&mut get_random_bytes(5242880));

        msg.pw_encrypt(&mut pw.clone(), 512);
        msg.pw_decrypt(&mut pw.clone(), 512);

        let res = msg.op_result.unwrap();
        assert!(res);
    }
    #[test]
    pub fn test_sym_enc_256() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(&mut get_random_bytes(5242880));

        msg.pw_encrypt(&mut pw.clone(), 256);
        msg.pw_decrypt(&mut pw.clone(), 256);

        let res = msg.op_result.unwrap();
        assert!(res);
    }
    #[test]
    fn test_key_gen_enc_dec_256() {
        //check conversion to and from bytes.
        let mut msg = Message::new(&mut get_random_bytes(5242880));
        let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), 256);

        msg.key_encrypt(key_pair.pub_key, 256);
        msg.key_decrypt(&key_pair.priv_key, 256);

        let res = msg.op_result.unwrap();
        assert!(res);
    }
}

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
