use super::{check, magnitude};
use crate::{DsaEncoding, DsaEncodingError};
use alloc::vec;
use alloc::vec::Vec;
use tc_asn1::{Asn1Integer, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// BC's `StandardDsaEncoding`: the DER SEQUENCE { INTEGER r, INTEGER s } of X9.62 and X.509.
/// Decoding takes DER alone, checked by encoding again as Bouncy Castle does.
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardDsaEncoding;

/// The DER SEQUENCE { r, s }. Variable time, only for public values.
fn der(r: &PaddedBigUint, s: &PaddedBigUint) -> Result<Vec<u8>, DsaEncodingError> {
    Asn1SequenceOf::new(vec![
        Asn1Integer::from_unsigned_bytes(&magnitude(r)),
        Asn1Integer::from_unsigned_bytes(&magnitude(s)),
    ])
    .encode_to_vec(&EncodingOptions::DER)
    .map_err(|_| DsaEncodingError::Malformed)
}

/// The whole length of a DER encoding with `content` bytes of contents. Variable time, only for
/// public values.
fn encoded_length(content: usize) -> usize {
    let length_octets = if content < 0x80 {
        1
    } else {
        1 + (usize::BITS - content.leading_zeros()).div_ceil(8) as usize
    };
    1 + length_octets + content
}

/// The value of an INTEGER, which must not be negative. Variable time, only for public values.
fn value(integer: &Asn1Integer) -> Result<PaddedBigUint, DsaEncodingError> {
    let bytes = integer
        .as_unsigned_bytes()
        .map_err(|_| DsaEncodingError::ValueOutOfRange)?;
    let Ok(value) = PaddedBigUint::from_be(bytes);
    Ok(value)
}

impl DsaEncoding for StandardDsaEncoding {
    /// BC's `GetMaxEncodingSize`: a SEQUENCE of two INTEGERs as long as n. Variable time, only
    /// for public values.
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize {
        let n = magnitude(order);
        let content = n.len().max(1) + usize::from(n.first().is_some_and(|byte| byte & 0x80 != 0));
        encoded_length(2 * encoded_length(content))
    }

    /// r and s must be below n. Variable time, only for public values.
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError> {
        check(order, r)?;
        check(order, s)?;
        let encoding = der(r, s)?;
        output
            .get_mut(..encoding.len())
            .ok_or(DsaEncodingError::OutputTooShort)?
            .copy_from_slice(&encoding);
        Ok(encoding.len())
    }

    /// Exactly two INTEGERs, no trailing bytes, in DER, both values in `[0, n)`. The length is
    /// bounded before anything is parsed. Variable time, only for public values.
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError> {
        let max_len = self.max_encoding_size(order);
        if encoding.len() > max_len {
            return Err(DsaEncodingError::Malformed);
        }
        let options = DecodingOptions::new(1, max_len, 2);
        let (used, sequence) = Asn1SequenceOf::<Asn1Integer>::decode(encoding, &options)
            .map_err(|_| DsaEncodingError::Malformed)?;
        let [r, s] = sequence.elements() else {
            return Err(DsaEncodingError::Malformed);
        };
        if used != encoding.len() {
            return Err(DsaEncodingError::Malformed);
        }
        let (r, s) = (value(r)?, value(s)?);
        check(order, &r)?;
        check(order, &s)?;
        if der(&r, &s)? != encoding {
            return Err(DsaEncodingError::Malformed);
        }
        Ok((r, s))
    }
}
