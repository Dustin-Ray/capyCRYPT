#[cfg(test)]
pub mod ops_tests {
    use std::time::Instant;

    use capycrypt::{
        sha3::aux_functions::byte_utils::get_random_bytes, KeyEncryptable, KeyPair, Message,
        SecParam, Signable, SpongeEncryptable,
    };

    #[test]
    pub fn test_sym_enc_512() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(get_random_bytes(5242880));

        assert!(msg.sha3_encrypt(&pw, &SecParam::D512).is_ok());
        assert!(msg.sha3_decrypt(&pw).is_ok());

        assert!(msg.op_result.is_ok());
    }
    #[test]
    pub fn test_sym_enc_256() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(get_random_bytes(5242880));

        assert!(msg.sha3_encrypt(&pw, &SecParam::D256).is_ok());
        assert!(msg.sha3_decrypt(&pw).is_ok());

        assert!(msg.op_result.is_ok());
    }
    #[test]
    fn test_key_gen_enc_dec_256() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let key_pair = KeyPair::new(
            &get_random_bytes(64),
            "test key".to_string(),
            &SecParam::D256,
        )
        .unwrap();

        assert!(msg.key_encrypt(&key_pair.pub_key, &SecParam::D256).is_ok());
        assert!(msg.key_decrypt(&key_pair.priv_key).is_ok());

        assert!(msg.op_result.is_ok());
    }

    #[test]
    fn test_key_gen_enc_dec_512() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let key_pair = KeyPair::new(
            &get_random_bytes(32),
            "test key".to_string(),
            &SecParam::D512,
        )
        .unwrap();

        assert!(msg.key_encrypt(&key_pair.pub_key, &SecParam::D512).is_ok());
        assert!(msg.key_decrypt(&key_pair.priv_key).is_ok());

        assert!(msg.op_result.is_ok());
    }
    #[test]
    pub fn test_signature_256() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let pw = get_random_bytes(64);
        let key_pair = KeyPair::new(&pw, "test key".to_string(), &SecParam::D256).unwrap();

        assert!(msg.sign(&key_pair, &SecParam::D256).is_ok());
        assert!(msg.verify(&key_pair.pub_key).is_ok());

        assert!(msg.op_result.is_ok());
    }

    // This test shouldnt have a huge variation between key sizes due to the fixed-time
    // nature of the lookup table being used for scalar decomposition in the
    // variable_base multiplication algorithm.
    // ## OBSERVATION:
    // key size larger than message has timing variation on larger values of i
    #[test]
    fn test_sig_timing_side_channel() {
        for i in 0..10 {
            let mut msg = Message::new(get_random_bytes(5242880));
            let pw = get_random_bytes(1 << i);
            let key_pair = KeyPair::new(&pw, "test key".to_string(), &SecParam::D512).unwrap();

            let now = Instant::now();
            let _ = msg.sign(&key_pair, &SecParam::D512);
            println!("{} needed {} microseconds", i, now.elapsed().as_micros());
            let _ = msg.verify(&key_pair.pub_key);
            assert!(msg.op_result.is_ok());
        }
    }
}
