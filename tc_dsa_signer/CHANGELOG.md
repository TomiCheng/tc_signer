# Changelog

All notable changes to `tc_dsa_signer` are documented in this file.

## 0.1.0 - 2026-11-25

Initial release.

### Added

- `DsaParameters`, `DsaValidationParameters`, `DsaPublicKey` and
  `DsaPrivateKey`, after Bouncy Castle's `DsaParameters`,
  `DsaValidationParameters`, `DsaPublicKeyParameters` and
  `DsaPrivateKeyParameters`. They are containers, checked by `validate`; the
  private key wipes x on drop and has no `Debug` or `PartialEq`.
- `DsaGroupGenerator` with `DsaGroupGenerationParams`, Bouncy Castle's
  `DsaParametersGenerator` and `DsaParameterGenerationParameters` under the
  names of `tc_dh_key`'s `DhGroupGenerator`: FIPS 186-2 over SHA-1 and FIPS
  186-3 over any digest of at least N bits, with g generated verifiably when a
  usage index is given. It takes its random source when it is constructed.
- `DsaKeyPairGenerator` with `DsaKeyGenerationParams`, after Bouncy Castle's
  `DsaKeyPairGenerator`, implementing `KeyPairGenerator` and
  `KeyPairGeneratorInit` of `tc_asym_cipher`.
- `DsaSigner`, after Bouncy Castle's `DsaSigner`, implementing `Dsa` and
  `DsaInit` of `tc_dsa` for both keys, over any `DsaKCalculator`.
- `DsaError` and `DsaSignerError`, `#[non_exhaustive]`.

### Compatibility

- `DsaSigner` draws another k when r or s is zero, as FIPS 186-4 4.6 asks;
  Bouncy Castle does not.
- `DsaParameters::validate` bounds p at 16384 bits before anything else, as
  Bouncy Castle does for a public key, and checks what the Montgomery
  arithmetic needs; `DsaPrivateKey::validate` checks that x is in
  `[1, q − 1]`, which Bouncy Castle does not.
- The unverifiable generator g draws its h with `tc_bigint`'s `random_range`,
  which reads the random source otherwise than Bouncy Castle, so the same
  source can give another g.
