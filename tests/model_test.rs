#[cfg(test)]
pub mod model_test {
    
    use cryptotool::{model::shake_functions::{encrypt_with_pw, decrypt_with_pw}};
    use cryptotool::sha3::aux_functions::byte_utils::get_random_bytes;

    #[test]
    pub fn test_sym_enc() {
        //test 1000 random encryptions and decryptions
            let pw = get_random_bytes();
            let message = get_random_bytes();
            let mut cg2 = encrypt_with_pw(&mut pw.clone(), &mut message.clone());
            let res = decrypt_with_pw(&mut pw.clone(), &mut cg2);
            println!("{:?}", res);
            assert!(hex::encode(message).eq(&hex::encode(res)));
    }
}