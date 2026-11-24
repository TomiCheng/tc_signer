//! The DSA family's contracts and the parts its signature algorithms share, after Bouncy
//! Castle's `IDsa`: a DSA signs the hash of a message as a pair of integers (r, s) in the group
//! order, and verifies such a pair.
//!
//! - [`Dsa`] and [`DsaInit`] are what an algorithm such as DSA, ECDSA or GOST R 34.10
//!   implements, [`DsaKCalculator`] gives it the secret k of each signature, and
//!   [`DsaEncoding`] writes (r, s) as bytes.
//! - [`DsaDigestSigner`] and [`Gost3410DigestSigner`] put a [`Dsa`] under the `Signer` of
//!   `tc_signer`: they hash the message, sign the hash and encode the signature.
//! - [`RandomDsaKCalculator`] draws k at random, and [`HMacDsaKCalculator`] works it out from
//!   the private value and the message as RFC 6979 does.
//! - [`StandardDsaEncoding`] writes (r, s) as a DER SEQUENCE and [`PlainDsaEncoding`] as r ‖ s.
//!
//! Every algorithm depends on this crate, so the examples live with them: the crate
//! documentation of an ECDSA or DSA crate shows a [`DsaDigestSigner`] over its algorithm.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod digest_signer;
mod digest_signer_error;
mod encoding;
mod encoding_error;
mod gost3410_digest_signer;
mod k_calculator;
mod traits;

pub use digest_signer::DsaDigestSigner;
pub use digest_signer_error::DsaDigestSignerError;
pub use encoding::{PlainDsaEncoding, StandardDsaEncoding};
pub use encoding_error::DsaEncodingError;
pub use gost3410_digest_signer::Gost3410DigestSigner;
pub use k_calculator::{HMacDsaKCalculator, RandomDsaKCalculator};
pub use traits::{Dsa, DsaEncoding, DsaInit, DsaKCalculator};
