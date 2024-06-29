#[test]
pub fn test_kem_enc_512() {
    use capycrypt::{
        kem::{encryptable::KEMEncryptable, keypair::kem_keygen},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    // Get 5mb random data
    let mut msg = Message::new(get_random_bytes(5242880));

    // Create a new ML-KEM public/private keypair
    let (kem_pub_key, kem_priv_key) = kem_keygen();
    // Encrypt the message
    assert!(msg.kem_encrypt(&kem_pub_key, SecParam::D256).is_ok());
    // Decrypt and verify
    assert!(msg.kem_decrypt(&kem_priv_key).is_ok());
}

#[test]
fn test_key_gen_enc_dec_256() {
    use capycrypt::{
        ecc::{encryptable::KeyEncryptable, keypair::KeyPair},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    // Get 5mb random data
    let mut msg = Message::new(get_random_bytes(5242880));

    // Create a new elliptic-curve public/private keypair
    let key_pair = KeyPair::new(
        &get_random_bytes(64),  // random password for key
        "test key".to_string(), // label
        SecParam::D256,         // bit-security for key
    )
    .unwrap();
    // Encrypt the message
    assert!(msg.key_encrypt(&key_pair.pub_key, SecParam::D256).is_ok());
    // Decrypt and verify
    assert!(msg.key_decrypt(&key_pair.priv_key).is_ok());
}

#[test]
fn test_key_gen_enc_dec_512() {
    use capycrypt::{
        ecc::{encryptable::KeyEncryptable, keypair::KeyPair},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    let mut msg = Message::new(get_random_bytes(5242880));
    let key_pair = KeyPair::new(
        &get_random_bytes(32),
        "test key".to_string(),
        SecParam::D512,
    )
    .unwrap();

    assert!(msg.key_encrypt(&key_pair.pub_key, SecParam::D512).is_ok());
    assert!(msg.key_decrypt(&key_pair.priv_key).is_ok());
}

#[test]
pub fn test_signature_256() {
    use capycrypt::{
        ecc::{keypair::KeyPair, signable::Signable},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };
    // Get random 5mb
    let mut msg = Message::new(get_random_bytes(5242880));
    // Create a new elliptic-curve public/private keypair
    let key_pair = KeyPair::new(
        &get_random_bytes(64),  // random password for key
        "test key".to_string(), // label
        SecParam::D256,         // bit-security for key
    )
    .unwrap();
    // Sign with 256 bits of security
    assert!(msg.sign(&key_pair, SecParam::D256).is_ok());
    // Verify signature
    assert!(msg.verify(&key_pair.pub_key).is_ok());
}

#[test]
fn test_hashable() {
    use capycrypt::{sha3::hashable::SpongeHashable, Message, SecParam};
    // Hash the empty string
    let mut data = Message::new(vec![]);
    // Obtained from echo -n "" | openssl dgst -sha3-256
    let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    // Compute a SHA3 digest with 128 bits of security
    data.compute_sha3_hash(SecParam::D256);
    assert!(hex::encode(data.digest) == expected);
}

#[test]
fn test_symmetric_encryptable() {
    use capycrypt::{
        aes::encryptable::AesEncryptable,
        sha3::{aux_functions::byte_utils::get_random_bytes, encryptable::SpongeEncryptable},
        Message, SecParam,
    };
    // Get a random password
    let pw = get_random_bytes(16);
    // Get 5mb random data
    let mut msg = Message::new(get_random_bytes(5242880));
    // Encrypt the data
    assert!(msg.aes_encrypt_ctr(&pw).is_ok());
    // Decrypt the data
    assert!(msg.aes_decrypt_ctr(&pw).is_ok());
    // Encrypt the data
    assert!(msg.sha3_encrypt(&pw, SecParam::D512).is_ok());
    // Decrypt and verify
    assert!(msg.sha3_decrypt(&pw).is_ok());
}

#[test]
pub fn test_signature_512() {
    use capycrypt::{
        ecc::{keypair::KeyPair, signable::Signable},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    let mut msg = Message::new(get_random_bytes(5242880));
    let pw = get_random_bytes(64);
    let key_pair = KeyPair::new(&pw, "test key".to_string(), SecParam::D512).unwrap();

    assert!(msg.sign(&key_pair, SecParam::D512).is_ok());
    assert!(msg.verify(&key_pair.pub_key).is_ok());
}

// This test shouldnt have a huge variation between key sizes due to the fixed-time
// nature of the lookup table being used for scalar decomposition in the
// variable_base multiplication algorithm.
// ## OBSERVATION:
// key size larger than message has timing variation on larger values of i
#[test]
fn test_sig_timing_side_channel() {
    use capycrypt::{
        ecc::{keypair::KeyPair, signable::Signable},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };
    use std::time::Instant;

    for i in 0..10 {
        let mut msg = Message::new(get_random_bytes(5242880));
        let pw = get_random_bytes(1 << i);
        let key_pair = KeyPair::new(&pw, "test key".to_string(), SecParam::D512).unwrap();

        let now = Instant::now();
        let _ = msg.sign(&key_pair, SecParam::D512);
        println!("{} needed {} microseconds", i, now.elapsed().as_micros());
        let _ = msg.verify(&key_pair.pub_key);
    }
}

#[test]
fn test_reading_writing_keypair() {
    use capycrypt::{
        ecc::keypair::KeyPair, sha3::aux_functions::byte_utils::get_random_bytes, SecParam,
    };

    use tempfile::tempdir;

    let key_pair = KeyPair::new(
        &get_random_bytes(32),
        "test key".to_string(),
        SecParam::D512,
    )
    .expect("Failed to create key pair");

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let temp_file_path = temp_dir.path().join("read_write_keypair.json");

    let _ = key_pair.write_to_file(temp_file_path.to_str().unwrap());
    let read_key_pair = KeyPair::read_from_file(temp_file_path.to_str().unwrap())
        .expect("Failed to read key pair from file");

    assert_eq!(key_pair, read_key_pair);
}

#[test]
pub fn test_signature_512_read_keypair_from_file() {
    use capycrypt::{
        ecc::{keypair::KeyPair, signable::Signable},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    use tempfile::tempdir;

    let mut msg = Message::new(get_random_bytes(5242880));
    let pw = get_random_bytes(64);

    let key_pair = KeyPair::new(&pw, "test key".to_string(), SecParam::D512)
        .expect("Failed to create key pair");

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let temp_file_path: std::path::PathBuf = temp_dir.path().join("read_write_keypair.json");

    let _ = key_pair.write_to_file(temp_file_path.to_str().unwrap());
    let read_key_pair = KeyPair::read_from_file(temp_file_path.to_str().unwrap())
        .expect("Failed to read key pair from file");

    assert!(msg.sign(&read_key_pair, SecParam::D512).is_ok());
    assert!(msg.verify(&read_key_pair.pub_key).is_ok());
}

#[test]
pub fn test_signature_512_read_message_from_file() {
    use capycrypt::{
        ecc::{keypair::KeyPair, signable::Signable},
        sha3::aux_functions::byte_utils::get_random_bytes,
        Message, SecParam,
    };

    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let temp_file_path: std::path::PathBuf = temp_dir.path().join("temp_message.json");
    Message::new(get_random_bytes(5242880))
        .write_to_file(temp_file_path.to_str().unwrap())
        .unwrap();

    let mut initial_msg = Message::read_from_file(temp_file_path.to_str().unwrap()).unwrap();

    let pw = get_random_bytes(64);
    let key_pair = KeyPair::new(&pw, "test key".to_string(), SecParam::D512).unwrap();

    assert!(initial_msg.sign(&key_pair, SecParam::D512).is_ok());

    initial_msg
        .write_to_file(temp_file_path.to_str().unwrap())
        .unwrap();

    let mut signed_msg = Message::read_from_file(temp_file_path.to_str().unwrap()).unwrap();

    assert!(signed_msg.verify(&key_pair.pub_key).is_ok());
}

#[cfg(test)]
mod decryption_test {
    use capycrypt::{
        ecc::{encryptable::KeyEncryptable, keypair::KeyPair},
        sha3::{aux_functions::byte_utils::get_random_bytes, encryptable::SpongeEncryptable},
        Message,
        SecParam::D512,
    };

    // Testing a security parameters whether the failed decryption preserves
    // the original encrypted text. If an encrypted text is decrypted with a wrong password,
    // then the original encrypted message should remain the same.
    #[test]
    fn test_sha3_decrypt_handling_bad_input() {
        let pw1 = get_random_bytes(64);
        let pw2 = get_random_bytes(64);

        // D512
        let mut new_msg = Message::new(get_random_bytes(523));
        let _ = new_msg.sha3_encrypt(&pw1, D512);
        let msg2 = new_msg.msg.clone();
        let res = new_msg.sha3_decrypt(&pw2);

        assert!(res.is_err());
        assert_eq!(msg2, new_msg.msg);
    }

    // Testing a security parameters whether the failed decryption preserves
    // the original encrypted text. If an encrypted text is decrypted with a wrong password,
    // then the original encrypted message should remain the same.
    #[test]
    fn test_key_decrypt_handling_bad_input() {
        let mut new_msg = Message::new(get_random_bytes(125));

        // D512
        let key_pair1 = KeyPair::new(&get_random_bytes(32), "test key".to_string(), D512).unwrap();
        let key_pair2 = KeyPair::new(&get_random_bytes(32), "test key".to_string(), D512).unwrap();

        let _ = new_msg.key_encrypt(&key_pair1.pub_key, D512);
        let new_msg2 = new_msg.msg.clone();
        let res = new_msg.key_decrypt(&key_pair2.priv_key);

        assert!(res.is_err());
        assert_eq!(*new_msg.msg, *new_msg2, "Message after reverting a failed decryption does not match the original encrypted message");
    }
}
