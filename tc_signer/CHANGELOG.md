# Changelog

All notable changes to `tc_signer` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- The `Signer` contract for the maximum signature size, `update` with the
  message in pieces, `generate_signature` into a caller-provided buffer,
  `verify_signature` and `reset`, and `SignerInit`, which initializes a signer
  from a key of type `P`; the Rust form of Bouncy Castle's `ISigner`.
- The `SignerWithRecovery` contract for the part of the message a signature
  carries, `has_full_message`, `recovered_message` and
  `update_with_recovered_message`; the Rust form of Bouncy Castle's
  `ISignerWithRecovery`.
- A doctest that implements the traits on a toy signer.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std`, needs no allocator, has no dependencies and contains no `unsafe`
  code.
- The traits make no timing promise; each signer documents its own.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
