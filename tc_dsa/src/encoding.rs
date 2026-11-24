mod plain;
mod standard;

pub use plain::PlainDsaEncoding;
pub use standard::StandardDsaEncoding;

use crate::DsaEncodingError;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};

/// The big-endian bytes without leading zeros; zero is empty. Variable time, only for public
/// values.
fn magnitude(value: &PaddedBigUint) -> Vec<u8> {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// BC's `CheckValue`: `value` must be below `order`. Variable time, only for public values.
fn check(order: &PaddedBigUint, value: &PaddedBigUint) -> Result<(), DsaEncodingError> {
    if value >= order {
        return Err(DsaEncodingError::ValueOutOfRange);
    }
    Ok(())
}
