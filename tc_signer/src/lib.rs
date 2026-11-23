//! Shared contracts for digital signatures, after Bouncy Castle's `ISigner`
//! and `ISignerWithRecovery`.
//!
//! This crate defines how to initialize a signer with a key, feed it a message
//! in pieces, and sign or verify; it implements no algorithm, digest or
//! signature encoding. A signature algorithm implements the traits, so that a
//! caller can sign with RSA, an elliptic-curve DSA or ML-DSA in the same way.
//!
//! # Using a signer
//!
//! Call [`SignerInit::init`] with a private key to sign or a public key to
//! verify, then add the message with [`Signer::update`], in as many pieces as
//! it comes in. [`Signer::generate_signature`] writes the signature into a
//! buffer of [`Signer::max_signature_size`] bytes and returns its length;
//! [`Signer::verify_signature`] tells whether a signature fits the message.
//! Either one leaves the signer ready for the next message under the same key,
//! and [`Signer::reset`] discards a message half fed.
//!
//! A signer that carries part of the message in the signature, as ISO/IEC
//! 9796-2 does, also implements [`SignerWithRecovery`].
//!
//! Accepted keys, the digest and encoding, the state left by a rejected
//! initialization and every timing guarantee belong to the signer, not to
//! these traits.
//!
//! # Implementing a signer
//!
//! A signer implements [`SignerInit`] for each key type it accepts and
//! [`Signer`] for the message. The toy signer below "signs" with the XOR of
//! the message bytes and its key byte; it shows the contract and is not a
//! signature.
//!
//! ```
//! use core::fmt;
//! use tc_signer::{Signer, SignerInit};
//!
//! #[derive(Debug, PartialEq)]
//! struct ToyError;
//!
//! impl fmt::Display for ToyError {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         f.write_str("toy signer failure")
//!     }
//! }
//!
//! impl core::error::Error for ToyError {}
//!
//! struct ToyKey(u8);
//!
//! struct Toy {
//!     key: Option<u8>,
//!     sum: u8,
//! }
//!
//! impl SignerInit<ToyKey> for Toy {
//!     type Error = ToyError;
//!
//!     fn init(&mut self, key: &ToyKey) -> Result<(), ToyError> {
//!         self.key = Some(key.0);
//!         self.sum = 0;
//!         Ok(())
//!     }
//! }
//!
//! impl Signer for Toy {
//!     type Error = ToyError;
//!
//!     fn max_signature_size(&self) -> usize {
//!         1
//!     }
//!
//!     fn update(&mut self, input: &[u8]) -> Result<(), ToyError> {
//!         self.key.ok_or(ToyError)?;
//!         self.sum = input.iter().fold(self.sum, |sum, byte| sum ^ byte);
//!         Ok(())
//!     }
//!
//!     fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, ToyError> {
//!         let key = self.key.ok_or(ToyError)?;
//!         *output.first_mut().ok_or(ToyError)? = self.sum ^ key;
//!         self.reset();
//!         Ok(1)
//!     }
//!
//!     fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, ToyError> {
//!         let key = self.key.ok_or(ToyError)?;
//!         let valid = signature == [self.sum ^ key];
//!         self.reset();
//!         Ok(valid)
//!     }
//!
//!     fn reset(&mut self) {
//!         self.sum = 0;
//!     }
//! }
//!
//! let mut signer = Toy { key: None, sum: 0 };
//! assert_eq!(signer.update(b"too soon"), Err(ToyError));
//!
//! signer.init(&ToyKey(0x42))?;
//! signer.update(b"attack ")?;
//! signer.update(b"at dawn")?;
//! let mut signature = [0; 1];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! signer.update(b"attack at dawn")?;
//! assert!(signer.verify_signature(&signature[..length])?);
//! # Ok::<(), ToyError>(())
//! ```
//!
//! # Features
//!
//! The crate is `no_std`, needs no allocator and has no features or
//! dependencies.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod traits;

pub use traits::{Signer, SignerInit, SignerWithRecovery};
