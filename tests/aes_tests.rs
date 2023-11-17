#[cfg(test)]

mod aes_tests {
    use capycrypt::aes::aes_modes::{encrypt_aes_ecb, decrypt_aes_ecb};
    use capycrypt::Message;

    // Tests from AESAVS pg17
    #[test]
    fn test_aes_128_ecb_encrypt() {
        let key_string = "10a58869d74be5a374cf867cfb473859";

        let mut input = Message::new(hex::decode("00000000000000000000000000000000").unwrap());

        encrypt_aes_ecb(&mut input.msg, key_string);

        let expected = "6d251e6944b051e04eaa6fb4dbf78465";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    // Tests from AESAVS pg17
    #[test]
    fn test_aes_128_ecb_decrypt() {
        let key_string = "10a58869d74be5a374cf867cfb473859";

        let mut input = Message::new(hex::decode("6d251e6944b051e04eaa6fb4dbf78465").unwrap());
        decrypt_aes_ecb(&mut input.msg , key_string);

        let expected = "00000000000000000000000000000000";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    // Tests from AESAVS pg17
    #[test]
    fn test_aes_192_ecb_encrypt() {
        let key_string = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

        let mut input = Message::new(hex::decode("00000000000000000000000000000000").unwrap());

        encrypt_aes_ecb(&mut input.msg, key_string);

        let expected = "0956259c9cd5cfd0181cca53380cde06";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    // Tests from AESAVS pg17
    #[test]
    fn test_aes_192_ecb_decrypt() {
        let key_string = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

        let mut input = Message::new(hex::decode("0956259c9cd5cfd0181cca53380cde06").unwrap());
        decrypt_aes_ecb(&mut input.msg , key_string);

        let expected = "00000000000000000000000000000000";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    // Tests from AESAVS pg18
    #[test]
    fn test_aes_256_ecb_encrypt() {
        let key_string = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

        let mut input = Message::new(hex::decode("00000000000000000000000000000000").unwrap());
        encrypt_aes_ecb(&mut *input.msg,  key_string);

        let expected = "46f2fb342d6f0ab477476fc501242c5f";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    // Tests from AESAVS pg18
    #[test]
    fn test_aes_256_ecb_decrypt() {
        let key_string = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

        let mut input = Message::new(hex::decode("46f2fb342d6f0ab477476fc501242c5f").unwrap());
        decrypt_aes_ecb(&mut input.msg , key_string);

        let expected = "00000000000000000000000000000000";
        assert_eq!(hex::encode(*input.msg), expected)
    }

}