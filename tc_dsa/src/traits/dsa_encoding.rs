use crate::DsaEncodingError;
use tc_bigint::PaddedBigUint;

/// BC's `IDsaEncoding`: writes a DSA signature (r, s) as bytes and reads it back, r and s each
/// in `[0, n)`, n the group order. Signatures are public, so the implementations are variable
/// time.
pub trait DsaEncoding {
    /// The most bytes an encoding takes for the order `order`. Variable time, only for public
    /// values.
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize;

    /// Writes (r, s) to the start of `output` and returns its length. Variable time, only for
    /// public values.
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError>;

    /// Reads (r, s) back. Variable time, only for public values.
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError>;
}
