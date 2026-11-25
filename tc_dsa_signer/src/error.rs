use crate::DsaError;
use core::fmt;

/// What `DsaSigner` turns down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DsaSignerError {
    /// Used before `init`.
    NotInitialized,
    /// Asked to sign after `init` with a public key.
    NotForSigning,
    /// Asked to verify after `init` with a private key.
    NotForVerifying,
    /// The key or its parameters do not pass their checks; the reason is inside.
    InvalidKey(DsaError),
}

impl fmt::Display for DsaSignerError {
    /// Writes the message of the error, in Bouncy Castle's words where it has them. Constant
    /// time; the formatter decides how long the writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("DSA private key required for signing"),
            Self::NotForVerifying => f.write_str("DSA public key required for verification"),
            Self::InvalidKey(error) => write!(f, "invalid DSA key: {error}"),
        }
    }
}

impl core::error::Error for DsaSignerError {}
