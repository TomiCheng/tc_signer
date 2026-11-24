# tc_dsa

[![crates.io](https://img.shields.io/crates/v/tc_dsa.svg)](https://crates.io/crates/tc_dsa)
[![docs.rs](https://docs.rs/tc_dsa/badge.svg)](https://docs.rs/tc_dsa)
[![CI](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The DSA family's contracts after Bouncy Castle's `IDsa`, and the parts its
algorithms share: the signers that hash a message and encode (r, s), the k
calculators, and the DER and plain encodings. DSA, ECDSA and GOST R 34.10 build
on it. `no_std` with `alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `DsaDigestSigner` — hashes the message, signs the hash with a `Dsa` and encodes (r, s).
- `Gost3410DigestSigner` — the same for the GOST signatures, with the signature as s ‖ r.
- `RandomDsaKCalculator` — draws k at random.
- `HMacDsaKCalculator` — works k out from the private value and the message, as RFC 6979 does.
- `StandardDsaEncoding` — (r, s) as a DER SEQUENCE, for X9.62 and X.509.
- `PlainDsaEncoding` — (r, s) as r ‖ s, for BSI TR-03111 and JWS.
- `DsaDigestSignerError` — what the digest signers turn down.
- `DsaEncodingError` — what the encodings turn down.

## Traits

- `Dsa` — signs a hash as (r, s) and verifies such a pair.
- `DsaInit` — keys a `Dsa`, with a private key to sign or a public one to verify.
- `DsaKCalculator` — gives the secret k of each signature.
- `DsaEncoding` — writes (r, s) as bytes and reads it back.

The digest signers implement `Signer` and `SignerInit` of
[`tc_signer`](https://crates.io/crates/tc_signer).

## Features

None; the crate always uses `alloc`.

## Usage

```rust
let ecdsa = EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
let mut signer = DsaDigestSigner::new(ecdsa, Sha256Digest::new());
signer.init(&private_key)?;
signer.update(b"hello")?;
let mut signature = vec![0; signer.max_signature_size()];
let length = signer.generate_signature(&mut signature)?;
```

## Security

Prefer `HMacDsaKCalculator`: a k that repeats or leaks gives away the private
key, and RFC 6979 does not depend on the random source at signing time. The
decoders take DER strictly and bound the length before they parse it. The
digest signers are constant time as far as the algorithm and the digest are;
the encodings are variable time, for public signatures.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
