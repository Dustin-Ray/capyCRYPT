#[cfg(test)]
mod aes_modes_tests {
    use capycrypt::{
        aes::encryptable::AesEncryptable, sha3::aux_functions::byte_utils::get_random_bytes,
        Message,
    };

    #[test]
    fn aes_128_cbc() {
        // Get a random key (16 bytes -> 128 bits)
        let key = get_random_bytes(16);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key); // Encrypt the input
        assert!(input.aes_decrypt_cbc(&key).is_ok()); // Verify operation success
    }

    #[test]
    fn aes_192_cbc() {
        // Get a random key (24 bytes -> 192 bits)
        let key = get_random_bytes(24);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key); // Encrypt the input
        assert!(input.aes_decrypt_cbc(&key).is_ok()); // Verify operation success
    }

    #[test]
    fn aes_256_cbc() {
        // Get a random key (32 bytes -> 256 bits)
        let key = get_random_bytes(32);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_cbc(&key); // Encrypt the input
        assert!(input.aes_decrypt_cbc(&key).is_ok()); // Verify operation success
    }

    #[test]
    fn aes_128_ctr() {
        // Get a random key (16 bytes -> 128 bits)
        let key = get_random_bytes(16);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_ctr(&key); // Encrypt the input
        assert!(input.aes_decrypt_ctr(&key).is_ok()); // Verify operation success
    }

    #[test]
    fn aes_192_ctr() {
        // Get a random key (24 bytes -> 192 bits)
        let key = get_random_bytes(24);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_ctr(&key); // Encrypt the input
        assert!(input.aes_decrypt_ctr(&key).is_ok()); // Verify operation success
    }

    #[test]
    fn aes_256_ctr() {
        // Get a random key (32 bytes -> 256 bits)
        let key = get_random_bytes(32);
        // Get 5mb random data
        let mut input = Message::new(get_random_bytes(5242880));

        input.aes_encrypt_ctr(&key); // Encrypt the input
        assert!(input.aes_decrypt_ctr(&key).is_ok()); // Verify operation success
    }
}

#[cfg(test)]
mod aes_functions_tests {
    use capycrypt::{
        aes::aes_functions::{apply_pcks7_padding, remove_pcks7_padding, xor_blocks},
        Message,
    };

    #[test]
    fn test_applying_padding() {
        let mut input = Message::new(hex::decode("00000000000000000000000000000000").unwrap());
        apply_pcks7_padding(&mut input.msg);

        let expected = "0000000000000000000000000000000010101010101010101010101010101010";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    #[test]
    fn test_removing_padding() {
        let mut input = Message::new(
            hex::decode("0000000000000000000000000000000010101010101010101010101010101010")
                .unwrap(),
        );
        remove_pcks7_padding(&mut input.msg);

        let expected = "00000000000000000000000000000000";
        assert_eq!(hex::encode(*input.msg), expected)
    }

    #[test]
    fn test_xor_blocks() {
        let mut a = hex::decode("10101010101010101010101010101010").unwrap();
        let b = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        xor_blocks(&mut a, &b);

        let expected = "efefefefefefefefefefefefefefefef";
        assert_eq!(hex::encode(a), expected)
    }
}
