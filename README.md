# tc_signer

A Rust workspace for digital signatures after Bouncy Castle. It holds
`tc_signer`, the contracts that every signature algorithm implements, the
Rust form of Bouncy Castle's `ISigner` and `ISignerWithRecovery`. Each crate is
published separately and keeps its own README and changelog.

[![CI](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_signer/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_signer`](tc_signer) | [![crates.io](https://img.shields.io/crates/v/tc_signer.svg)](https://crates.io/crates/tc_signer) [![docs.rs](https://docs.rs/tc_signer/badge.svg)](https://docs.rs/tc_signer) | The `Signer`, `SignerInit` and `SignerWithRecovery` contracts, the Rust form of Bouncy Castle's `ISigner` and `ISignerWithRecovery`. `no_std`, no allocator, no dependencies, no `unsafe`. The traits make no timing promise; each signer states its own. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and without
an allocator.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build in this workspace, tests included. The workspace lock tracks the
latest dependency releases, so CI on stable tests what a user on a current
toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, runs the tests on Rust 1.85.0, checks the `wasm32-unknown-unknown`
and `aarch64-unknown-none` targets and each crate's dependency set on each
target, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

Before a release, check each archive and run publication validation from a
committed checkout:

```text
cargo package -p <crate> --list --locked
cargo publish -p <crate> --dry-run --locked
```

The archive must include both license texts, the crate README, the changelog
and the source, and no `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
