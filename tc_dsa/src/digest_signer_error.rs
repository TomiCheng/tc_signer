use crate::DsaEncodingError;
use core::fmt;

/// What `DsaDigestSigner` and `Gost3410DigestSigner` turn down; `E` is the error of the DSA
/// underneath.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DsaDigestSignerError<E> {
    /// Used before `init`.
    NotInitialized,
    /// Asked to sign after `init` with a public key.
    NotForSigning,
    /// Asked to verify after `init` with a private key.
    NotForVerifying,
    /// The DSA underneath failed.
    Dsa(E),
    /// The signature cannot be encoded, as when the output buffer is too short.
    Encoding(DsaEncodingError),
}

impl<E: fmt::Display> fmt::Display for DsaDigestSignerError<E> {
    /// Writes the message of the error, in Bouncy Castle's words where it has them. Constant
    /// time; the formatter decides how long the writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => {
                f.write_str("DsaDigestSigner not initialized for signature generation.")
            }
            Self::NotForVerifying => {
                f.write_str("DsaDigestSigner not initialized for verification")
            }
            Self::Dsa(error) => error.fmt(f),
            Self::Encoding(error) => write!(f, "unable to encode signature: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for DsaDigestSignerError<E> {}
