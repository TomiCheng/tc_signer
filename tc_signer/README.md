# tc_signer

[![crates.io](https://img.shields.io/crates/v/tc_signer.svg)](https://crates.io/crates/tc_signer)
[![docs.rs](https://docs.rs/tc_signer/badge.svg)](https://docs.rs/tc_signer)
[![CI](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared contracts for digital signatures, after Bouncy Castle's `ISigner` and
`ISignerWithRecovery`: a signer takes a message in pieces and signs it, or
verifies a signature over it, whatever the algorithm underneath. `no_std`, no
allocator, no dependencies, no `unsafe`, Rust 1.85 or later.

## Traits

- `Signer` — `update` with the message, then `generate_signature` or `verify_signature`, and `reset`.
- `SignerInit<P>` — `init` with a key of type `P`: a private key signs, a public key verifies.
- `SignerWithRecovery` — the part of the message a signature carries, as ISO/IEC 9796-2 does.

## Features

None; the crate needs neither `std` nor `alloc`.

## Usage

```toml
[dependencies]
tc_signer = "0.1.0"
```

```rust,ignore
use tc_signer::{Signer, SignerInit};

fn sign<S: Signer + SignerInit<K>, K>(signer: &mut S, key: &K, message: &[u8]) -> Vec<u8> {
    signer.init(key).expect("a signing key");
    signer.update(message).expect("initialized");
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).expect("signed");
    signature[..length].to_vec()
}
```

## Security

The traits make no timing promise; each signer documents its own, and what it
does with a rejected key. A signature that does not verify is `Ok(false)`, not
an error.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
