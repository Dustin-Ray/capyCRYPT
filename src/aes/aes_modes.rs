use crate::aes::aes_functions::AES;

// Electroninc Code Book (ECB): The message is divided into blocks, and each block 
// is encrypted separately.
pub fn encrypt_aes_ecb(input: &mut Vec<u8>, key: &str) {
    let key_schedule = AES::new(key);
    let round_key = &key_schedule.round_key;

    for block_index in (0..input.len()).step_by(16) {
        AES::encrypt_block(input, block_index, &round_key);
    }
}

pub fn decrypt_aes_ecb(input: &mut Vec<u8>, key: &str) {
    let key_schedule = AES::new(key);
    let round_key = &key_schedule.round_key;

    for block_index in (0..input.len()).step_by(16) {
        AES::decrypt_block(input, block_index, &round_key);
    }
}

// Future Modes of Operations are:
// - Cipher Block Chaining (CBC)
// - Output feedback (OFB)
// - Counter (CTR)
// - Galois Counter Mode (GCM)