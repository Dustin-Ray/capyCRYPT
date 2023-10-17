use capycrypt::{
    curves::EdCurves::{self, E222},
    KeyEncryptable, KeyPair, Message, PwEncryptable, Signable,
};

use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
use criterion::{criterion_group, criterion_main, Criterion};

const SELECTED_CURVE: EdCurves = E222;

/// Symmetric encrypt and decrypt roundtrip
fn sym_enc(pw: &mut Vec<u8>, mut msg: Message) {
    msg.pw_encrypt(&mut pw.clone(), 256);
    msg.pw_decrypt(&mut pw.clone(), 256);
}

/// Asymmetric encrypt and decrypt roundtrip + keygen
fn key_gen_enc_dec(pw: &mut Vec<u8>, mut msg: Message) {
    let key_pair = KeyPair::new(pw, "test key".to_string(), SELECTED_CURVE, 256);
    msg.key_encrypt(&key_pair.pub_key, 256);
    msg.key_decrypt(&key_pair.priv_key, 256);
}

/// Signature generation + verification roundtrip
pub fn sign_verify(mut key_pair: KeyPair, mut msg: Message) {
    msg.sign(&mut key_pair.priv_key, 512);
    msg.verify(key_pair.pub_key, 512);
}

fn bench_sign_verify(c: &mut Criterion) {
    c.bench_function("Signature Generation + Verification Roundtrip", |b| {
        b.iter(|| {
            sign_verify(
                KeyPair::new(&get_random_bytes(16), "test key".to_string(), SELECTED_CURVE, 512),
                Message::new(&mut get_random_bytes(5242880)),
            )
        });
    });
}

fn bench_sym_enc(c: &mut Criterion) {
    c.bench_function("Symmetric Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            sym_enc(
                &mut get_random_bytes(64),
                Message::new(&mut get_random_bytes(5242880)),
            )
        });
    });
}

fn bench_key_gen_enc_dec(c: &mut Criterion) {
    c.bench_function("Keygen + Asymmetric Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| {
            key_gen_enc_dec(
                &mut KeyPair::new(&get_random_bytes(32), "test key".to_string(), SELECTED_CURVE, 256).priv_key,
                Message::new(&mut get_random_bytes(5242880)),
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
