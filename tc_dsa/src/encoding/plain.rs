use super::{check, magnitude};
use crate::{DsaEncoding, DsaEncodingError};
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// BC's `PlainDsaEncoding`: r ‖ s, each big-endian over the length of n in bytes, the format
/// of BSI TR-03111 and JWS.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainDsaEncoding;

impl DsaEncoding for PlainDsaEncoding {
    /// Twice the length of n in bytes. Variable time, only for public values.
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize {
        magnitude(order).len() * 2
    }

    /// r and s must be below n, and `output` must hold both. Variable time, only for public
    /// values.
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError> {
        check(order, r)?;
        check(order, s)?;
        let length = magnitude(order).len();
        let output = output
            .get_mut(..length * 2)
            .ok_or(DsaEncodingError::OutputTooShort)?;
        output.fill(0);
        for (half, value) in output.chunks_mut(length).zip([r, s]) {
            let bytes = magnitude(value);
            half[length - bytes.len()..].copy_from_slice(&bytes);
        }
        Ok(length * 2)
    }

    /// The length must be exactly twice that of n in bytes, and both values below n. Variable
    /// time, only for public values.
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError> {
        let length = magnitude(order).len();
        if encoding.len() != length * 2 {
            return Err(DsaEncodingError::Malformed);
        }
        let (r, s) = encoding.split_at(length);
        let Ok(r) = PaddedBigUint::from_be(r);
        let Ok(s) = PaddedBigUint::from_be(s);
        check(order, &r)?;
        check(order, &s)?;
        Ok((r, s))
    }
}
