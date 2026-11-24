//! `StandardDsaEncoding` and `PlainDsaEncoding` over the (r, s) of RFC 6979 A.2.5 (P-256,
//! SHA-256, "sample") and the order of P-256: DER is taken strictly, values are bounded, and the
//! errors. The signatures themselves are tested in the crates that implement `Dsa`.

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{DsaEncoding, DsaEncodingError, PlainDsaEncoding, StandardDsaEncoding};

const R: &str = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
const S: &str = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
const N: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    let Ok(value) = PaddedBigUint::from_be(&bytes(hex));
    value
}

#[test]
fn der_decoding_accepts_only_strict_der_with_values_below_the_order() {
    let n = integer(N);
    let der = [bytes("3046022100"), bytes(R), bytes("022100"), bytes(S)].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &der),
        Ok((integer(R), integer(S)))
    );
    for malformed in [
        // A trailing byte.
        [der.clone(), vec![0]].concat(),
        // A length in two bytes, which is not DER.
        [bytes("308146022100"), bytes(R), bytes("022100"), bytes(S)].concat(),
        // An extra leading zero, not the shortest INTEGER.
        [
            bytes("3047022200"),
            bytes("00"),
            bytes(R),
            bytes("022100"),
            bytes(S),
        ]
        .concat(),
        // A single INTEGER.
        [bytes("3023022100"), bytes(R)].concat(),
    ] {
        assert_eq!(
            StandardDsaEncoding.decode(&n, &malformed),
            Err(DsaEncodingError::Malformed)
        );
    }
    // A negative value and one not below n.
    let negative = [bytes("30250220"), bytes(R), bytes("020101")].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &negative),
        Err(DsaEncodingError::ValueOutOfRange)
    );
    let too_large = [bytes("3046022100"), bytes(N), bytes("022100"), bytes(S)].concat();
    assert_eq!(
        StandardDsaEncoding.decode(&n, &too_large),
        Err(DsaEncodingError::ValueOutOfRange)
    );
}

#[test]
fn der_decoding_bounds_the_sequence_before_converting_its_integers() {
    // With order 7, the longest possible signature occupies eight bytes.
    let oversized = bytes("300702020100020101");
    assert_eq!(
        StandardDsaEncoding.decode(&integer("07"), &oversized),
        Err(DsaEncodingError::Malformed)
    );

    // Three small integers still fit the P-256 byte limit.
    let extra_child = bytes("3009020101020102020103");
    assert_eq!(
        StandardDsaEncoding.decode(&integer(N), &extra_child),
        Err(DsaEncodingError::Malformed)
    );
}

#[test]
fn plain_decoding_needs_twice_the_order_length_and_values_below_it() {
    let n = integer(N);
    let plain = [bytes(R), bytes(S)].concat();
    assert_eq!(
        PlainDsaEncoding.decode(&n, &plain),
        Ok((integer(R), integer(S)))
    );
    assert_eq!(
        PlainDsaEncoding.decode(&n, &plain[1..]),
        Err(DsaEncodingError::Malformed)
    );
    let too_large = [bytes(N), bytes(S)].concat();
    assert_eq!(
        PlainDsaEncoding.decode(&n, &too_large),
        Err(DsaEncodingError::ValueOutOfRange)
    );
    assert_eq!(
        PlainDsaEncoding.encode(&n, &integer(R), &integer(S), &mut [0; 63]),
        Err(DsaEncodingError::OutputTooShort)
    );
    // A short value is padded with zeros.
    let mut output = [0xff; 64];
    PlainDsaEncoding
        .encode(
            &n,
            &PaddedBigUint::from(1u8),
            &PaddedBigUint::from(2u8),
            &mut output,
        )
        .unwrap();
    assert_eq!(output[..32], [vec![0; 31], vec![1]].concat()[..]);
    assert_eq!(output[32..], [vec![0; 31], vec![2]].concat()[..]);
}
