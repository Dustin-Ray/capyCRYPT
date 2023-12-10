use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
use capycrypt::{KeyEncryptable, KeyPair, Message, PwEncryptable, Signable};
use criterion::{criterion_group, criterion_main, Criterion};

const BIT_SECURITY: u64 = 512;

/// Symmetric encrypt and decrypt roundtrip
fn sym_enc(pw: &mut Vec<u8>, mut msg: Message) {
    msg.pw_encrypt_sha3(&pw, BIT_SECURITY);
    msg.pw_decrypt_sha3(&pw);
}

/// Asymmetric encrypt and decrypt roundtrip + keygen
fn key_gen_enc_dec(pw: &mut Vec<u8>, mut msg: Message) {
    let key_pair = KeyPair::new(pw, "test key".to_string(), BIT_SECURITY);
    msg.key_encrypt(&key_pair.pub_key, BIT_SECURITY);
    msg.key_decrypt(&key_pair.priv_key);
}

/// Signature generation + verification roundtrip
pub fn sign_verify(mut key_pair: KeyPair, mut msg: Message) {
    msg.sign(&mut key_pair, BIT_SECURITY);
    msg.verify(&key_pair.pub_key);
}

fn bench_sign_verify(c: &mut Criterion) {
    c.bench_function("e448 + SHA3-512 Sign + Verify Roundtrip 5mb", |b| {
        b.iter(|| {
            sign_verify(
                KeyPair::new(&get_random_bytes(16), "test key".to_string(), BIT_SECURITY),
                Message::new(get_random_bytes(5242880)),
            )
        });
    });
}

fn bench_sym_enc(c: &mut Criterion) {
    c.bench_function("SHA3-512 Symmetric enc + dec 5mb", |b| {
        b.iter(|| {
            sym_enc(
                &mut get_random_bytes(64),
                Message::new(get_random_bytes(5242880)),
            )
        });
    });
}

fn bench_key_gen_enc_dec(c: &mut Criterion) {
    c.bench_function("e448 + SHA3-512 Asymmetric enc + dec 5mb", |b| {
        b.iter(|| {
            key_gen_enc_dec(
                &mut KeyPair::new(&get_random_bytes(32), "test key".to_string(), BIT_SECURITY)
                    .priv_key,
                Message::new(get_random_bytes(5242880)),
            )
        });
    });
}

criterion_group!(
    benches,
    bench_sym_enc,
    bench_key_gen_enc_dec,
    bench_sign_verify
);
criterion_main!(benches);
