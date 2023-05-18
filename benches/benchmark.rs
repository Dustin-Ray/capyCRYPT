use criterion::{criterion_group, criterion_main, Criterion};
use capycrypt::{
    model::shake_functions::{encrypt_with_pw, decrypt_with_pw, gen_keypair, encrypt_with_key, decrypt_with_key, sign_with_key, verify_signature}, 
    curve::e521::e521_module::get_e521_point};
    use std::borrow::BorrowMut;
    use capycrypt::sha3::aux_functions::byte_utils::get_random_bytes;

/// Symmetric encrypt and decrypt roundtrip
fn sym_enc(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let mut cg2 = Box::new(encrypt_with_pw(&mut pw.clone(), &mut message));
    decrypt_with_pw(&mut pw.clone(), &mut cg2.borrow_mut());
}

/// Asymmetric encrypt and decrypt roundtrip + keygen
fn key_gen_enc_dec(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let owner = "test key".to_string();
    let key_obj = gen_keypair(&mut pw.clone(), owner);
    let x = key_obj.pub_x;
    let y = key_obj.pub_y;
    let mut pub_key = get_e521_point(x, y);
    let mut enc = encrypt_with_key(&mut pub_key, &mut message);
    decrypt_with_key(&mut pw.clone(), enc.borrow_mut());
}

/// Signature generation + verification roundtrip
pub fn sign_verify(pw: &mut Vec<u8>, mut message: Box<Vec<u8>>) {
    let key_obj = gen_keypair(&mut pw.clone(), "test".to_string());
    let x = key_obj.pub_x;
    let y = key_obj.pub_y;
    let mut key = get_e521_point(x, y);
    let sig = sign_with_key(&mut pw.clone(), &mut message);
    verify_signature(&sig, &mut key, &mut message);
}

fn bench_sign_verify(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Signature Generation + Verification", |b| b.iter(|| sign_verify(&mut pw.clone() , message.clone())));
}

fn bench_sym_enc(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Symmetric Encrypt + Decrypt", |b| b.iter(|| sym_enc(&mut pw.clone() , message.clone())));
}

fn bench_key_gen_enc_dec(c: &mut Criterion) {
    let pw = get_random_bytes(16);
    let message = Box::new(get_random_bytes(5242880).to_owned());
    c.bench_function("Keygen + Asymmetric Encrypt + Decrypt", |b| b.iter(|| key_gen_enc_dec(&mut pw.clone() , message.clone())));
}

criterion_group!(benches, bench_sym_enc, bench_key_gen_enc_dec, bench_sign_verify);
criterion_main!(benches);