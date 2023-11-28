# capyCRYPT - A Complete Rust Cryptosystem

[![Build Status](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml/badge.svg)](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/capycrypt?style=flat-square)](https://crates.io/crates/capycrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/drcapybara/capyCRYPT/blob/master/LICENSE.txt) 

A complete Rust cryptosystem implementing [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) & [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) paired with a variety of Edwards curves. An academic exercise in cryptographic algorithm design.

## Features
- **SHA-3:** NIST-Compliant Secure Hash Algorithm 3 (SHA-3) implementation for generating cryptographic hash values.

- **Edwards Elliptic Curve:** A variety of Edwards curve implementations for elliptic curve cryptography (ECC) operations are offered, varying in security and efficiency. Curves can be easily interchanged in asymmetric operations to suit the needs of the application.

- **AES:** NIST-Compliant Advanced Encryption Standard (AES) implementation for encrypting and decrypting data.

## Supported Operations
- **Message Digest:** Computes hash of a given message, with adjustable digest lengths.
- **MACs:** Computes message authentication code of a given message, with adjustable bit security.
- **Shared Secret Key:** Symmetric message encryption and decryption.
- **Public Key Cryptography:** Asymmetric message encryption under public key, decryption with secret key.
- **Zero-Knowledge:** Prove knowledge of secret information with Schnorr/ECDHIES signatures.

## Installation
Add the following line to your `Cargo.toml` file:
```toml
capycrypt = "0.5.0"
```

### Note: Building the `rug` Crate

This library uses an FFI to GMP by means of the rug crate. To successfully build the `rug` crate, please ensure that you have the `m4` library installed on your system. `m4` is a prerequisite for certain components of the build process. You can install it on debian-like systems with:
```bash
apt-get install m4
```

## Quick Start
### Compute Digest:
```rust
use capycrypt::{Hashable, Message};
// Hash the empty string
let mut data = Message::new(vec![]);
// Obtained from OpenSSL
let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
// Compute a SHA3 digest with 128 bits of security
data.compute_sha3_hash(256);
assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
```

### Symmetric Encrypt/Decrypt:
```rust
use capycrypt::{
    Message,
    PwEncryptable,
    sha3::{aux_functions::byte_utils::get_random_bytes}
};
// Get a random password
let pw = get_random_bytes(64);
// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));
// Encrypt the data with 256 bits of security
msg.pw_encrypt(&pw, 512);
// Decrypt the data
msg.pw_decrypt(&pw);
// Verify operation success
assert!(msg.op_result.unwrap());
```

### AES-CBC Symmetric Encrypt/Decrypt:
```rust
use capycrypt::{
    Message,
    AESEncryptable,
    sha3::{aux_functions::byte_utils::get_random_bytes}
};
// Get a random 128-bit password
let key = get_random_bytes(16);
// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));
// Encrypt the data
msg.aes_encrypt_cbc(&key);
// Decrypt the data
msg.aes_encrypt_cbc(&key);
// Verify operation success
assert!(msg.op_result.unwrap());
```

### Asymmetric Encrypt/Decrypt:
```rust
use capycrypt::{
    KeyEncryptable,
    KeyPair,
    Message,
    sha3::aux_functions::byte_utils::get_random_bytes,
    curves::EdCurves::E448};

// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));
// Create a new private/public keypair
let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), E448, 512);

// Encrypt the message
msg.key_encrypt(&key_pair.pub_key, 512);
// Decrypt the message
msg.key_decrypt(&key_pair.priv_key);
// Verify
assert!(msg.op_result.unwrap());
```

### Schnorr Signatures:
```rust
use capycrypt::{
    Signable,
    KeyPair,
    Message,
    sha3::aux_functions::byte_utils::get_random_bytes,
    curves::EdCurves::E448};
// Get random 5mb
let mut msg = Message::new(get_random_bytes(5242880));
// Get a random password
let pw = get_random_bytes(64);
// Generate a signing keypair
let key_pair = KeyPair::new(&pw, "test key".to_string(), E448, 512);
// Sign with 256 bits of security
msg.sign(&key_pair, 512);
// Verify signature
msg.verify(&key_pair.pub_key);
// Assert correctness
assert!(msg.op_result.unwrap());
```

## Benches
This library uses the criterion crate for benches. Running:
```bash
cargo bench
```
conducts benchmarks in order from lowest security to highest. For example, the lowest security configuration available in this library is the pairing of E222 with cSHAKE256, while the highest security offered is E521 paired with cSHAKE512.

I make no claims as to the security of this library. It probably shouldn't be used for anything serious. If you find cool ways to make it better, open a PR and I'll gladly engage.