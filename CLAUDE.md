# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
  The `Signer`, `SignerInit` and `SignerWithRecovery` signatures in particular
  are shared by every signature crate built on `tc_signer`.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs are short and written for crates.io: the badge block, a
  sentence or two on what the crate is, the "Types", "Traits" and "Features"
  lists, a usage example of ten lines or fewer, a short security note and the
  license. Behaviour belongs in the rustdoc, and validation and release
  commands in the root README.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std` and contains no `unsafe` code, which each crate root forbids.
`tc_signer` needs no allocator; `tc_dsa` always uses `alloc`.

`tc_signer` holds the contracts alone: `Signer` and `SignerInit<P>`, after
Bouncy Castle's `ISigner`, and `SignerWithRecovery`, after
`ISignerWithRecovery`. Initialization and signing are separate traits, and a
signer implements `SignerInit` once for each key type it accepts, a private key
to sign and a public key to verify. A signer hashes and encodes the message
itself, so `update` takes the message, not a digest; a signature algorithm
that works on a digest, such as the DSA family, sits under a signer that adds
the digest and the encoding. The signature goes into a caller-provided buffer,
so the crate needs no allocator. A signature that does not verify is
`Ok(false)`, not an error. The traits make no timing promise; each signer
documents its own. The crate has no dependencies and no features.

`tc_dsa` holds the DSA family's contracts after Bouncy Castle's `IDsa` and the
parts its algorithms share. `Dsa` signs a hash as (r, s) and verifies such a
pair, `DsaInit<P>` keys it, `DsaKCalculator` gives the secret k, and
`DsaEncoding` writes (r, s) as bytes. `DsaDigestSigner` and
`Gost3410DigestSigner` put a `Dsa` under `Signer`: they hash the message, sign
the hash and encode the signature, as DER or plain, or as GOST's s ‖ r.
`RandomDsaKCalculator` draws k at random and `HMacDsaKCalculator` follows RFC
6979, rekeying before every draw after the first as 3.2 h.3 asks, where Bouncy
Castle rekeys only after a k out of range. The encodings take DER strictly and
bound an encoding by the order's maximum size before parsing it. Every
algorithm, ECDSA and DSA among them, depends on this crate, so none of them can
be a dependency of its tests: the examples and the signing tests live in the
algorithm crates, and its own tests cover the encodings and the k calculators.
`tests/documentation.rs` requires the digest signers' and the encodings'
declarations to say "constant time" or "variable time", exactly one; the
traits make no timing promise, and each k calculator states its own.

Rust 1.85 is guaranteed for every build in the workspace, tests included.
Besides `tc_*` crates, `tc_dsa` depends on `rand_core` and, through
`tc_bigint`, `num-traits`, and its tests on `rand`; all build on 1.85.
`.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
`Cargo.lock` tracks the latest releases. Adding any third-party dependency or
dev-dependency hands part of the 1.85 guarantee to that crate; raise it before
doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in each crate's
`README.md` — and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
