use core::fmt;

/// What the DSA signature encodings turn down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DsaEncodingError {
    /// r or s is negative or not below the group order.
    ValueOutOfRange,
    /// The encoding has the wrong length or form, or is not DER.
    Malformed,
    /// The output buffer cannot hold the encoding.
    OutputTooShort,
}

impl fmt::Display for DsaEncodingError {
    /// Writes the message of the error, in Bouncy Castle's words where it has them. Constant
    /// time; the formatter decides how long the writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ValueOutOfRange => "Value out of range",
            Self::Malformed => "Malformed signature",
            Self::OutputTooShort => "the output buffer is too small",
        })
    }
}

impl core::error::Error for DsaEncodingError {}
