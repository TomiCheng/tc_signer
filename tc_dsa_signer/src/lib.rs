//! DSA of FIPS 186, after Bouncy Castle: the domain parameters and their validation data, the
//! keys, the key pair generator, the group generator of FIPS 186-2 and 186-3, and [`DsaSigner`],
//! which implements `Dsa` of `tc_dsa`. To sign a whole message and encode the signature, put the
//! signer under `tc_dsa`'s `DsaDigestSigner`.
//!
//! A group is generated once and shared; key pairs are generated over it.
//!
//! ```no_run
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::{DsaDigestSigner, HMacDsaKCalculator};
//! use tc_dsa_signer::{
//!     DsaGroupGenerationParams, DsaGroupGenerator, DsaKeyGenerationParams, DsaKeyPairGenerator,
//!     DsaSigner,
//! };
//! use tc_sha::Sha256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // The group: L = 2048 and N = 256 of FIPS 186-3, over SHA-256; this takes seconds.
//! let mut group_generator = DsaGroupGenerator::with_digest(rand::rng(), Sha256Digest::new());
//! group_generator.init_fips186_3(&DsaGroupGenerationParams::new(2048, 256, 80))?;
//! let params = group_generator.generate_group()?;
//!
//! // The signer's key pair: x stays here and is wiped on drop, y goes to the verifier.
//! let mut generator = DsaKeyPairGenerator::new(rand::rng());
//! generator.init(&DsaKeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // Signing: the message hashed with SHA-256, k worked out as RFC 6979 does, the signature
//! // in DER.
//! let dsa = || DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
//! let mut signer = DsaDigestSigner::new(dsa(), Sha256Digest::new());
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! // Verifying: a public key from elsewhere is checked first, then the same digest verifies.
//! public_key.validate()?;
//! let mut verifier = DsaDigestSigner::new(dsa(), Sha256Digest::new());
//! verifier.init(&public_key)?;
//! verifier.update(b"hello")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod dsa_error;
mod error;
mod group_generator;
mod key_pair_generator;
mod math;
mod params;
mod signer;

pub use dsa_error::DsaError;
pub use error::DsaSignerError;
pub use group_generator::DsaGroupGenerator;
pub use key_pair_generator::DsaKeyPairGenerator;
pub use params::{
    DsaGroupGenerationParams, DsaKeyGenerationParams, DsaParameters, DsaPrivateKey, DsaPublicKey,
    DsaValidationParameters,
};
pub use signer::DsaSigner;
