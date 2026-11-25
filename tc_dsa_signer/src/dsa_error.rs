use core::fmt;

/// The parameters, keys and generator settings that Bouncy Castle's DSA parameter classes and
/// generators turn down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DsaError {
    /// A generation before `init`.
    NotInitialized,
    /// p is not an odd number above 2.
    InvalidModulus,
    /// p has more than 16384 bits, the default bound of Bouncy Castle's `DsaMaxSize`.
    ModulusTooLarge,
    /// q is not an odd number above 2, or not below p.
    InvalidOrder,
    /// g is not in `[2, p - 1]`.
    InvalidGenerator,
    /// The public value y is not in `[2, p - 2]`, or not in the subgroup of order q.
    InvalidPublicKey,
    /// The private value x is not in `[1, q - 1]`.
    InvalidPrivateKey,
    /// The p of FIPS 186-2 must have 512 to 1024 bits, a multiple of 64.
    InvalidSize,
    /// The L and N of FIPS 186-3 are not (1024, 160), (2048, 224), (2048, 256) or (3072, 256).
    InvalidLengths,
    /// The digest is shorter than N bits, or not SHA-1 for FIPS 186-2.
    UnsuitableDigest,
    /// The certainty of the primality tests is 0.
    InvalidCertainty,
}

impl fmt::Display for DsaError {
    /// Writes the message of the error, in Bouncy Castle's words where it has them. Constant
    /// time; the formatter decides how long the writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the generator is not initialized",
            Self::InvalidModulus => "p must be an odd integer above 2",
            Self::ModulusTooLarge => "DSA modulus out of range",
            Self::InvalidOrder => "q must be an odd integer above 2 and below p",
            Self::InvalidGenerator => "g must lie in [2, p - 1]",
            Self::InvalidPublicKey => "y value does not appear to be in correct group",
            Self::InvalidPrivateKey => "x must lie in [1, q - 1]",
            Self::InvalidSize => "size must be from 512 - 1024 and a multiple of 64",
            Self::InvalidLengths => {
                "L and N must be (1024, 160), (2048, 224 or 256) or (3072, 256)"
            }
            Self::UnsuitableDigest => "Digest output size too small for value of N",
            Self::InvalidCertainty => "certainty must be positive",
        })
    }
}

impl core::error::Error for DsaError {}
