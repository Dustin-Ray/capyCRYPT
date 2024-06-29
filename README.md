# capyCRYPT - A Complete Rust Cryptosystem
<p align="center">
  <img src="./cc.jpg" width="520" height="320">
</p>


[![Build Status](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml/badge.svg)](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/capycrypt?style=flat-square)](https://crates.io/crates/capycrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/drcapybara/capyCRYPT/blob/master/LICENSE.txt) 

A complete Rust cryptosystem implementing: 

- AES: [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- SHA3: [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) 
- ML-KEM: [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)
- E448: [Ed448-Goldilocks Curve](https://eprint.iacr.org/2015/625.pdf)

These primitives form the basis of a platform supporting a wide variety of cryptographic operations, which are detailed below.

## Security
This library is built with love as an academic excercise in cryptographic algorithm design. Despite how awesome and cool it is, it probably shouldn't be used for anything serious right now. If you find ways to make it even better, open an issue or PR and we'll gladly engage.

## Features
- **AES:** NIST-Compliant **Advanced Encryption Standard** (AES) implementation for encrypting and decrypting data.

- **Edwards Elliptic Curve:** High-performance, side-channel resistant instance of the **Ed448-Goldilocks** curve for asymmetric operations.

- **SHA-3:** NIST-Compliant **Secure Hash Algorithm 3** (SHA-3) implementation for generating cryptographic hash values, symmetric keystreams, and PRNGs.

- **ML-KEM 768:** NIST Initial Public Draft (IPD)-Compliant **Module Ring-Learning With Errors Key Encapsulation Mechanism** (ML-KEM) for quantum-safe asymmetric key and message exchange.

## Supported Operations
- **Message Digest:** Computes hash of a given message, with adjustable digest lengths.
- **MACs:** Computes message authentication code of a given message, with adjustable bit security.
- **Shared Secret Key:** Symmetric message encryption and decryption.
- **Public Key Cryptography:** Asymmetric message encryption under public key, decryption with secret key.
- **Signatures** Prove and verify knowledge of secret information with Schnorr/ECDHIES signatures.
- **Quantum-Safe Message Exchange:** ML-KEM + SHA3 sponge for quantum-safe symmetric messaging and key exchange.

## Installation
Add the following line to your `Cargo.toml` file:
```bash
cargo add capycrypt
```

## Quick Start
### Quantum-Secure Encrypt/Decrypt:
```rust
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
msg.kem_encrypt(&kem_pub_key, SecParam::D256);
// Decrypt and verify
assert!(msg.kem_decrypt(&kem_priv_key).is_ok());
```

### Elliptic-Curve Encrypt/Decrypt:
```rust
use capycrypt::{
    ecc::{encryptable::KeyEncryptable, keypair::KeyPair},
    sha3::aux_functions::byte_utils::get_random_bytes,
    Message, SecParam,
};

// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));

// Create a new elliptic-curve public/private keypair
let key_pair = KeyPair::new(
    &get_random_bytes(64),   // random password for key
    "test key".to_string(),  // label
    SecParam::D256,         // bit-security for key
);
// Encrypt the message
msg.key_encrypt(&key_pair.pub_key, SecParam::D256);
// Decrypt and verify
assert!(msg.key_decrypt(&key_pair.priv_key).is_ok());
```

### Symmetric Encrypt/Decrypt:
```rust
use capycrypt::{
    aes::encryptable::AesEncryptable,
    sha3::{aux_functions::byte_utils::get_random_bytes, 
    encryptable::SpongeEncryptable},
    Message, SecParam,
};
// Get a random password
let pw = get_random_bytes(16);
// Get 5mb random data
let mut msg = Message::new(get_random_bytes(5242880));
// Encrypt the data
msg.aes_encrypt_ctr(&pw);
// Decrypt the data
assert!(msg.aes_decrypt_ctr(&pw).is_ok());
// Encrypt the data
msg.sha3_encrypt(&pw, SecParam::D512);
// Decrypt and verify
assert!(msg.sha3_decrypt(&pw).is_ok());
```

### Schnorr Signatures:
```rust
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
    SecParam::D256,        // bit-security for key
);
// Sign with 128 bits of security
msg.sign(&key_pair, SecParam::D256);
// Verify signature
assert!(msg.verify(&key_pair.pub_key).is_ok());
```

### Compute Digest:
```rust
use capycrypt::{sha3::hashable::SpongeHashable, Message, SecParam};
// Hash the empty string
let mut data = Message::new(vec![]);
// Obtained from echo -n "" | openssl dgst -sha3-256
let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
// Compute a SHA3 digest with 128 bits of security
data.compute_sha3_hash(SecParam::D256);
assert!(hex::encode(data.digest) == expected);
```

## Performance
This library uses the criterion crate for benches. Running:
```bash
cargo bench
```
conducts benchmarks over parameter sets in order from lowest security to highest.

Symmetric operations compare well to openSSL. On an Intel® Core™ i7-10710U × 12, our adaption of in-place keccak from the [XKCP](https://github.com/XKCP/XKCP) achieves a runtime of approximately 20 ms to digest 5mb of random data, vs approximately 17 ms in openSSL.

## (Plausible) Post-Quantum Security
This library pairs ML-KEM-768 to a SHA3-sponge construction for a quantum-safe public-key cryptosystem. It offers theoretic quantum-security through the use of the KEM and sponge primitives, which are both based on problems conjectured to be hard to solve for a quantum adversary. This design seeds the SHA-3 sponge with the secret shared through the KEM + a session nonce, which then faciliates high-performance symmetric encryption/decryption of arbitrary-length messages.

Our construction is non-standard, has not been subject to peer review, and lacks any formal audit. Our [MLKEM library](https://github.com/drcapybara/capyKEM) itself is a work in progress and only supports the NIST-II security parameter-set of 768 (which is the recommended parameter, but we don't want the other sets to feel left out). Furthermore, the current FIPS 203 IPD is, (as the name indicates), a draft, and final details about secure implementation may be subject to change. Our design currently exists in this library purely as an academic curiosity. Use it at your own risk, we provide no guarantee of security, reliability, or efficiency.

## Acknowledgements
The authors wish to sincerely thank Dr. Paulo Barreto for the initial design of this library as well as the theoretical backbone of the Edward's curve functionality. We also wish to extend gratitude to the curve-dalek authors [here](https://github.com/crate-crypto/Ed448-Goldilocks) and [here](https://docs.rs/curve25519-dalek/4.1.1/curve25519_dalek/) for the excellent reference implementations and exemplary instances of rock-solid cryptography. 

Our KEM implementation is inspired by the excellent [go implementation](https://pkg.go.dev/filippo.io/mlkem768) by Filippo Valsorda and the initial rust-crypto implementation by the great Tony Arcieri [here](https://crates.io/crates/ml-kem).
