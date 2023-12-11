# capyCRYPT - A Complete Rust Cryptosystem
<p align="center">
  <img src="./img.webp" width="350" height="350">
</p>


[![Build Status](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml/badge.svg)](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/capycrypt?style=flat-square)](https://crates.io/crates/capycrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/drcapybara/capyCRYPT/blob/master/LICENSE.txt) 

A complete Rust cryptosystem implementing [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) & [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) paired to the ed448 Golidlocks curve. An academic exercise in cryptographic algorithm design.

## Security
This library is built with love as an academic excercise in cryptographic algorithm design. Despite how awesome and cool it is, it probably shouldn't be used for anything serious. If you find ways to make it even better, open an issue or PR and we'll gladly engage.


## Features
- **AES:** NIST-Compliant Advanced Encryption Standard (AES) implementation for encrypting and decrypting data.

- **Edwards Elliptic Curve:** High-performance, side-channel resistant instance of the [Ed448-Goldilocks](https://crates.io/crates/tiny_ed448_goldilocks) curve for asymmetric operations.

- **SHA-3:** NIST-Compliant Secure Hash Algorithm 3 (SHA-3) implementation for generating cryptographic hash values, symmetric keystreams, and PRNGs.


## Supported Operations
- **Message Digest:** Computes hash of a given message, with adjustable digest lengths.
- **MACs:** Computes message authentication code of a given message, with adjustable bit security.
- **Shared Secret Key:** Symmetric message encryption and decryption.
- **Public Key Cryptography:** Asymmetric message encryption under public key, decryption with secret key.
- **Zero-Knowledge:** Prove knowledge of secret information with Schnorr/ECDHIES signatures.

## Installation
Add the following line to your `Cargo.toml` file:
```bash
cargo add capycrypt
```

## Quick Start
### Compute Digest:
```rust
use capycrypt::{Hashable, Message};
// Hash the empty string
let mut data = Message::new(vec![]);
// Obtained from echo -n "" | openssl dgst -sha3-256
let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
// Compute a SHA3 digest with 128 bits of security
data.compute_sha3_hash(256);
assert!(hex::encode(data.digest.unwrap().to_vec()) == expected);
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
    sha3::aux_functions::byte_utils::get_random_bytes
};

// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));
// Create a new private/public keypair
let key_pair = KeyPair::new(&get_random_bytes(32), "test key".to_string(), 512);

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
};
// Get random 5mb
let mut msg = Message::new(get_random_bytes(5242880));
// Get a random password
let pw = get_random_bytes(64);
// Generate a signing keypair
let key_pair = KeyPair::new(&pw, "test key".to_string(), 512);
// Sign with 256 bits of security
msg.sign(&key_pair, 512);
// Verify signature
msg.verify(&key_pair.pub_key);
// Assert correctness
assert!(msg.op_result.unwrap());
```

## Performance
This library uses the criterion crate for benches. Running:
```bash
cargo bench
```
conducts benchmarks in order from lowest security to highest. For example, the lowest security configuration available in this library is the pairing of E222 with cSHAKE256, while the highest security offered is E521 paired with cSHAKE512.

Symmetric operations compare well to openSSL. On an Intel® Core™ i7-10710U × 12, our adaption of in-place keccak from the [XKCP](https://github.com/XKCP/XKCP) achieves a runtime of approximately 20 ms to digest 5mb of random data, vs approximately 17 ms in openSSL.

## Acknowledgements

The authors wish to sincerely thank Dr. Paulo Barreto for the general design of this library as well as the curve functionality. We also wish to extend gratitude to the curve-dalek authors [here](https://github.com/crate-crypto/Ed448-Goldilocks) and [here](https://docs.rs/curve25519-dalek/4.1.1/curve25519_dalek/) for the excellent reference implementations and exemplary instances of rock-solid cryptography.
