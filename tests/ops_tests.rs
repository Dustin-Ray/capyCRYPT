#[cfg(test)]
pub mod ops_tests {
    use capycrypt::{
        curves::EdCurves::E448, sha3::aux_functions::byte_utils::get_random_bytes, KeyEncryptable,
        KeyPair, Message, PwEncryptable, Signable,
    };
    use std::time::Instant;

    #[test]
    pub fn test_sym_enc_512() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(get_random_bytes(5242880));

        msg.pw_encrypt(&pw, 256);
        msg.pw_decrypt(&pw);

        assert!(msg.op_result.unwrap());
    }
    #[test]
    pub fn test_sym_enc_256() {
        let pw = get_random_bytes(64);
        let mut msg = Message::new(get_random_bytes(5242880));

        msg.pw_encrypt(&pw, 256);
        msg.pw_decrypt(&pw);

        assert!(msg.op_result.unwrap());
    }
    #[test]
    fn test_key_gen_enc_dec_256() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), E448, 256);

        msg.key_encrypt(&key_pair.pub_key, 256);
        msg.key_decrypt(&key_pair.priv_key);

        assert!(msg.op_result.unwrap());
    }

    #[test]
    fn test_key_gen_enc_dec_512() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), E448, 512);

        msg.key_encrypt(&key_pair.pub_key, 512);
        msg.key_decrypt(&key_pair.priv_key);

        assert!(msg.op_result.unwrap());
    }
    #[test]
    pub fn test_signature_512() {
        let mut msg = Message::new(get_random_bytes(5242880));
        let pw = get_random_bytes(64);
        let key_pair = KeyPair::new(&pw, "test key".to_string(), E448, 512);

        msg.sign(&key_pair, 512);
        msg.verify(&key_pair.pub_key);

        assert!(msg.op_result.unwrap());
    }
}
