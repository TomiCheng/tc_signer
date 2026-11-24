# Changelog

All notable changes to `tc_dsa` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Dsa` and `DsaInit`, after Bouncy Castle's `IDsa`. Initialization and signing
  are separate traits, and an algorithm implements `DsaInit` once for each key
  type it accepts.
- `DsaKCalculator`, after `IDsaKCalculator`, with `RandomDsaKCalculator` and
  `HMacDsaKCalculator`, RFC 6979's deterministic k. Bouncy Castle's two `Init`s
  are one, since a random calculator takes its random source when it is
  constructed, so `IsDeterministic` is not needed.
- `DsaEncoding`, after `IDsaEncoding`, with `StandardDsaEncoding` (DER) and
  `PlainDsaEncoding` (r ‖ s).
- `DsaDigestSigner` and `Gost3410DigestSigner`, after Bouncy Castle's classes
  of those names, implementing `Signer` and `SignerInit` of `tc_signer`.
- `DsaDigestSignerError` and `DsaEncodingError`, `#[non_exhaustive]`.

### Compatibility

- `HMacDsaKCalculator` draws again as RFC 6979 3.2 h.3 asks also when a signer
  calls `next_k` once more because r or s was zero; Bouncy Castle rekeys only
  after a k out of range. The two differ only in that case, of probability
  about 2^-256.
- The k calculators panic in `init` for an order below two, where an empty
  range would otherwise draw forever.
- `StandardDsaEncoding` bounds an encoding by the order's maximum size before
  it parses it, and turns down a SEQUENCE of more than two values.
- `Gost3410DigestSigner` reports a signature that is not twice the length of
  the hash as not verifying, where Bouncy Castle throws on one too short and
  ignores the extra bytes of one too long.
