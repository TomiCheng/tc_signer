use alloc::vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint, Word};
use tc_zeroize::Zeroize;

/// BC's `WNafUtilities.GetNafWeight`: the number of nonzero digits in the NAF of k, which is the
/// number of 1 bits of 3k XOR k, worked out limb by limb with the carry. Constant time: every limb
/// is visited.
pub(crate) fn naf_weight(limbs: &[Limb]) -> u32 {
    let (mut top, mut carry, mut weight): (Word, Word, u32) = (0, 0, 0);
    for limb in limbs {
        let x = limb.to_word();
        let doubled = (x << 1) | top;
        top = x >> (Word::BITS - 1);
        let (sum, low) = doubled.overflowing_add(x);
        let (sum, high) = sum.overflowing_add(carry);
        carry = Word::from(low) + Word::from(high);
        weight += (sum ^ x).count_ones();
    }
    weight + (top + carry).count_ones()
}

/// BC's `new BigInteger(bits, random)`: ⌈bits / 8⌉ random bytes read big-endian, with the extra
/// bits of the top byte cleared. The bytes drawn are wiped after use. Constant time: only the
/// length decides.
pub(crate) fn random_bits(rng: &mut dyn CryptoRng, bits: u32) -> PaddedBigUint {
    let length = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    if let Some(first) = bytes.first_mut() {
        *first &= 0xFF >> (length as u32 * 8 - bits);
    }
    let Ok(value) = PaddedBigUint::from_be(&bytes);
    bytes.zeroize();
    value
}

/// BC's `BigIntegers.CreateRandomInRange(low, high)` for a small low: random values of the bit
/// length of high until one falls in `[low, high]`. Constant time in the values drawn: the
/// comparisons do not branch on them, and discarded candidates are wiped; only how many are
/// drawn shows, which has nothing to do with the value kept.
pub(crate) fn random_in_range(
    rng: &mut dyn CryptoRng,
    low: &PaddedBigUint,
    high: &PaddedBigUint,
) -> PaddedBigUint {
    loop {
        let mut value = random_bits(rng, high.bits());
        if &value >= low && &value <= high {
            return value;
        }
        value.zeroize();
    }
}
