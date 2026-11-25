# tc_dsa_signer

[![crates.io](https://img.shields.io/crates/v/tc_dsa_signer.svg)](https://crates.io/crates/tc_dsa_signer)
[![docs.rs](https://docs.rs/tc_dsa_signer/badge.svg)](https://docs.rs/tc_dsa_signer)
[![CI](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

DSA of FIPS 186 after Bouncy Castle: the domain parameters, the keys, group
generation by FIPS 186-2 and 186-3, key pair generation, and the signer, which
implements `Dsa` of [`tc_dsa`](https://crates.io/crates/tc_dsa). `no_std` with
`alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `DsaParameters` — p, q, g and the optional validation data; `validate` runs the checks.
- `DsaValidationParameters` — the seed, counter and usage index a group was generated from.
- `DsaPublicKey` — y with its parameters; `validate` checks its range and its subgroup.
- `DsaPrivateKey` — x with its parameters, wiped on drop.
- `DsaGroupGenerationParams` — the L, N and certainty of a FIPS 186-3 group.
- `DsaGroupGenerator` — generates a group by FIPS 186-2 or 186-3.
- `DsaKeyGenerationParams` — the parameters a key pair is generated over.
- `DsaKeyPairGenerator` — draws x and works out y = g^x mod p.
- `DsaSigner` — signs a hash as (r, s) and verifies such a pair.
- `DsaError` — what the checks and the generators turn down.
- `DsaSignerError` — what the signer turns down.

## Traits

`DsaSigner` implements `Dsa` and `DsaInit` of `tc_dsa` for both keys, and
`DsaKeyPairGenerator` implements `KeyPairGenerator` and `KeyPairGeneratorInit`
of [`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher). To sign a whole
message, put the signer under `tc_dsa`'s `DsaDigestSigner`.

## Features

None; the crate always uses `alloc`.

## Usage

```rust
let dsa = DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
let mut signer = DsaDigestSigner::new(dsa, Sha256Digest::new());
signer.init(&private_key)?;
signer.update(b"hello")?;
let mut signature = vec![0; signer.max_signature_size()];
let length = signer.generate_signature(&mut signature)?;
```

## Security

FIPS 186-5 no longer approves DSA for new signatures; use it for existing keys
and data. Check every public key from a peer with `validate`, prefer
`HMacDsaKCalculator` for k, and use groups of 2048 bits or more. Signing and key
generation are constant time in the private value and k; verification, the
checks and group generation are variable time, for public values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
