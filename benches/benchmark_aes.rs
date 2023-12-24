use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
use capycrypt::{AesEncryptable, Message};
use rand::{distributions::Alphanumeric, Rng};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use capycrypt::aes::aes_functions::{apply_pcks7_padding, remove_pcks7_padding};

use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

fn generate_random_data(size: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect()
}

/// Symmetric encrypt and decrypt roundtrip with aes rust
fn sym_enc_rust_aes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut iv = get_random_bytes(16);
    let mut result = Vec::with_capacity(data.len());

    // XOR function for byte arrays
    fn xor_blocks(a: &mut [u8], b: &[u8]) {
        for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
            *a_byte ^= *b_byte;
        }
    }
    let mut data_vec = data.to_vec();
    // Padding function
    apply_pcks7_padding(&mut data_vec);

    // Encrypt blocks using CBC mode
    for block_index in (0..data.len()).step_by(16) {
        let block = &data[block_index..block_index + 16];
        let mut temp_block = block.to_vec();

        // XOR current block with IV (or the previous cipher text)
        xor_blocks(&mut temp_block, &iv);

        // Encrypt the block
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut temp_block));

        // Update IV for the next block
        iv.copy_from_slice(&temp_block);

        // Append the encrypted block to the result
        result.extend_from_slice(&temp_block);
    }

    // Save the ciphertext to be decrypted
    let ciphertext = result.clone();

    // Decrypt blocks using CBC mode
    iv.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
    for block_index in (0..ciphertext.len()).step_by(16).skip(16) {
        let block = &mut result[block_index..block_index + 16];
        let prev_block = &ciphertext[block_index - 16..block_index];

        // Save the current block for later use
        let curr_block = block.to_vec();

        // Decrypt the block
        cipher.decrypt_block(GenericArray::from_mut_slice(block));

        // XOR decrypted block with IV (or the previous ciphertext block)
        xor_blocks(block, prev_block);

        // Update IV for the next block
        iv.copy_from_slice(&curr_block);
    }

    // Remove padding at the end (if needed)
    remove_pcks7_padding(&mut result);

    result
}



/// Symmetric encrypt and decrypt roundtrip
fn sym_cbc_enc(key: &mut Vec<u8>, data: &[u8]) {
    let mut msg = Message::new(data.to_owned());
    let _ = msg.aes_encrypt_cbc(&key);
    let _ = msg.aes_decrypt_cbc(&key);
}

/// Symmetric encrypt and decrypt roundtrip for AES in CTR mode
fn sym_ctr_enc(key: &mut Vec<u8>, data: &[u8]) {
    let mut msg = Message::new(data.to_owned());
    let _ = msg.aes_encrypt_ctr(&key);
    let _ = msg.aes_decrypt_ctr(&key);
}

// Benchmark AES encryption and decryption roundtrip
fn bench_aes_cbc_enc(c: &mut Criterion) {

    let data = generate_random_data(5 * 1024 * 1024);
    let mut key = get_random_bytes(32); // Generate key if needed

    c.bench_function("Rust AES-256-CBC Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            sym_enc_rust_aes(black_box(&key), black_box(&data));
        });
    });

    c.bench_function("capyCRYPT AES-256-CBC Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            sym_cbc_enc(&mut key, black_box(&data));
        });
    });
}

// Benchmark AES encryption and decryption roundtrip
fn bench_aes_ctr_enc(c: &mut Criterion) {

    let data = generate_random_data(5 * 1024 * 1024);
    let mut key = get_random_bytes(32); // Generate key if needed

    c.bench_function("capyCRYPT AES-256-CTR Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            sym_ctr_enc(&mut key, black_box(&data));
        });
    });
}

criterion_group!(benches, bench_aes_cbc_enc, bench_aes_ctr_enc);
criterion_main!(benches);
