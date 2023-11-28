#[cfg(test)]

mod aes_modes_tests {
    use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
    use capycrypt::{Message, AesEncryptable};

    #[test]
    fn aes_128_cbc() {
        let key = get_random_bytes(16); // 16 bytes -> 128 bits
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key);
        input.aes_decrypt_cbc(&key);

        assert!(input.op_result.unwrap());
    }

    #[test]
    fn aes_192_cbc() {
        let key = get_random_bytes(24); // 24 bytes -> 192 bits
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key);
        input.aes_decrypt_cbc(&key);

        assert!(input.op_result.unwrap());
    }

    #[test]
    fn aes_256_cbc() {
        let key = get_random_bytes(32); // 32 bytes -> 256 bits
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key);
        input.aes_decrypt_cbc(&key);

        assert!(input.op_result.unwrap());
    }
}

#[cfg(test)]
mod aes_functions_tests {
    use capycrypt::aes::aes_functions::{apply_pcks7_padding, remove_pcks7_padding, xor_blocks};
    use capycrypt::Message;

    #[test]
    fn test_applying_padding() {
        let mut input = Message::new(hex::decode("00000000000000000000000000000000").unwrap());
        apply_pcks7_padding(&mut input.msg);

        let expected = "0000000000000000000000000000000010101010101010101010101010101010";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    #[test]
    fn test_removing_padding() {
        let mut input = Message::new(hex::decode("0000000000000000000000000000000010101010101010101010101010101010").unwrap());
        remove_pcks7_padding(&mut input.msg);

        let expected = "00000000000000000000000000000000";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    #[test]
    fn test_xor_blocks() {
        let mut a = hex::decode("10101010101010101010101010101010").unwrap();
        let b = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        xor_blocks(&mut a, &b, 0);

        let expected = "efefefefefefefefefefefefefefefef";
        assert_eq!(hex::encode(a), expected)
    }
}