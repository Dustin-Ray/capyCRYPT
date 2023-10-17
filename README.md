# capyCRYPT - A Complete Rust Cryptosystem

[![Build Status](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml/badge.svg)](https://github.com/drcapybara/capyCRYPT-Rust/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/capycrypt?style=flat-square)](https://crates.io/crates/capycrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/drcapybara/capyCRYPT/blob/master/LICENSE.txt) 

A complete Rust cryptosystem implementing FIPS 202 paired with a variety of Edwards curves. An academic exercise in cryptographic algorithm design.

## Features
- **SHA-3:** NIST-Compliant Secure Hash Algorithm 3 (SHA-3) implementation for generating cryptographic hash values.

- **Edwards Elliptic Curve:** A variety of Edwards curve implementations for elliptic curve cryptography (ECC) operations are offered, varying in security and efficiency. Curves can be easily interchanged in asymmetric operations to suit the needs of the application.

## Supported Operations
- **Message Digest:** Computes hash of a given message, with adjustable digest lengths.
- **MACs:** Computes message authentication code of a given message, with adjustable bit security.
- **Shared Secret Key:** Symmetric message encryption and decryption.
- **Public Key Cryptography:** Asymmetric message encryption under public key, decryption with secret key.
- **Zero-Knowledge:** Prove knowledge of secret information with Schnorr/ECDHIES signatures.

## Installation
Add the following line to your `Cargo.toml` file:
```toml
capycrypt = "0.3.1"
```

### Note: Building the `rug` Crate

This library uses an FFI to GMP by means of the rug crate. To successfully build the `rug` crate, please ensure that you have the `m4` library installed on your system. `m4` is a prerequisite for certain components of the build process. You can install it on debian-like systems with:
```bash
apt-get install m4
```

## Benches
This library uses the criterion crate for benches. Running:
```bash
cargo bench
```
Conducts benchmarks in order from lowest security to highest. For example, the lowest security configuration available in this library is the pairing of E222 with cSHAKE256, while the highest security offered is E521 paired with cSHAKE512.

I make no claims as to the security of this library. It probably shouldn't be used for anything serious. If you find cool ways to make it better, open a PR and I'll gladly engage.