use capycrypt::curves::{
    ArbitraryPoint, EdCurvePoint,
    EdCurves::{self, E521},
};
use capycrypt::ops::{
    decrypt_with_key, decrypt_with_pw, encrypt_with_key, encrypt_with_pw, gen_keypair,
    sign_with_key, verify_signature,
};
use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use std::borrow::BorrowMut;
const SELECTED_CURVE: EdCurves = E521;

/// Symmetric encrypt and decrypt roundtrip
fn sym_enc(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let mut cg2 = Box::new(encrypt_with_pw(&mut pw.clone(), &mut message, 512));
    decrypt_with_pw(&mut pw.clone(), &mut cg2.borrow_mut(), 512);
}

/// Asymmetric encrypt and decrypt roundtrip + keygen
fn key_gen_enc_dec(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let owner = "test key".to_string();
    let key_obj = gen_keypair(&mut pw.clone(), owner, 512);
    let x = key_obj.pub_x;
    let y = key_obj.pub_y;
    let pub_key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
    let mut enc = encrypt_with_key(pub_key, &mut message, 512);
    decrypt_with_key(&mut pw.clone(), enc.borrow_mut(), 512);
}

/// Signature generation + verification roundtrip
pub fn sign_verify(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let key_obj = gen_keypair(&mut pw.clone(), "test".to_string(), 512);
    let x = key_obj.pub_x;
    let y = key_obj.pub_y;
    let key = EdCurvePoint::arbitrary_point(SELECTED_CURVE, x, y);
    let sig = sign_with_key(&mut pw.clone(), &mut message, 512);
    verify_signature(&sig, key, &mut message, 512);
}

fn bench_sign_verify(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Signature Generation + Verification Roundtrip", |b| {
        b.iter(|| sign_verify(&mut pw.clone(), message.clone()))
    });
}

fn bench_sym_enc(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Symmetric Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| sym_enc(&mut pw.clone(), message.clone()))
    });
}

fn bench_key_gen_enc_dec(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Keygen + Asymmetric Encrypt + Decrypt Roundtrip", |b| {
        b.iter(|| key_gen_enc_dec(&mut pw.clone(), message.clone()))
    });
}

criterion_group!(
    benches,
    bench_sym_enc,
    bench_key_gen_enc_dec,
    bench_sign_verify
);
criterion_main!(benches);
