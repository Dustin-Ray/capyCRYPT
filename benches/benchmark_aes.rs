use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
use capycrypt::{AesEncryptable, Message};
use criterion::{criterion_group, criterion_main, Criterion};

/// Symmetric encrypt and decrypt roundtrip
fn sym_enc(key: &mut Vec<u8>, mut msg: Message) {
    let _ = msg.aes_encrypt_cbc(&key);
    let _ = msg.aes_decrypt_cbc(&key);
}

// Benchmark AES encryption and decryption roundtrip
fn bench_aes_enc(c: &mut Criterion) {
    c.bench_function("AES-256-CBC Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            sym_enc(
                &mut get_random_bytes(32),
                Message::new(get_random_bytes(5242880)),
            )
        });
    });
}

criterion_group!(benches, bench_aes_enc);
criterion_main!(benches);
