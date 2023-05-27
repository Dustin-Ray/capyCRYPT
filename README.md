# capyCRYPT - A Complete Rust Cryptosystem

[![Build Status](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml/badge.svg)](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/capycrypt?style=flat-square)](https://crates.io/crates/capycrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/auditless/cairo-template/blob/main/LICENSE) 

A Rust library implementing FIPS 202 paired with a non-standard Edwards-521 curve. Engineered for performance; supports arbitrary message size.

## Features
- **SHA-3:** NIST-Compliant Secure Hash Algorithm 3 (SHA-3) implementation for generating cryptographic hash values.

- **Edwards Elliptic Curve:** A variety of Edwards curve implementations for elliptic curve cryptography (ECC) operations are offered, varying in security and efficiency. Curves can be easily interchanged in asymmetric operations to suit the needs of the application.

## Supported Operations
- **Message Digest:** Computes 512 bit hash of a given message.
- **MACs:** Computes 512 bit message authentication code of a given message.
- **Passkey:** Symmetric message encryption and decryption, and MAC generation.
- **Public Key Cryptography:** Asymmetric message encryption under public key, decryption with secret key.
- **Zero-Knowledge:** Prove knowledge of secret information with Schnorr/ECDHIES signatures.

## Installation
Add the following line to your `Cargo.toml` file:

```toml
capycrypt = "0.3.0"
```

## Benches
This library uses the criterion crate for benches. Bench various curves and SHA-3 security levels with:
```bash
cargo bench
```
