use crate::{DsaError, DsaGroupGenerationParams, DsaParameters, DsaValidationParameters};
use alloc::string::ToString;
use alloc::vec;
use core::fmt::Display;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomRange};
use tc_digest::Digest;
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;
use tc_sha::Sha1Digest;

/// BC's `DsaParametersGenerator`, named after `DhGroupGenerator` of `tc_dh_key`: generates p, q
/// and g with their validation data by FIPS 186-2 (SHA-1, p of 512 to 1024 bits) or FIPS 186-3
/// (L and N from [`DsaGroupGenerationParams`]). It takes its random source when it is
/// constructed; the digest is SHA-1 by default.
pub struct DsaGroupGenerator<R, D = Sha1Digest> {
    rng: R,
    digest: D,
    settings: Option<Settings>,
}

/// What `init` keeps: the lengths, the certainty and the procedure.
#[derive(Clone, Copy)]
struct Settings {
    l: u32,
    n: u32,
    certainty: u32,
    fips186_3: bool,
    usage_index: Option<u8>,
}

impl<R> DsaGroupGenerator<R> {
    /// A generator that draws from `rng` and hashes with SHA-1, before `init`. Constant time.
    pub fn new(rng: R) -> Self {
        Self::with_digest(rng, Sha1Digest::new())
    }
}

impl<R, D> DsaGroupGenerator<R, D> {
    /// A generator that draws from `rng` and hashes with `digest`, before `init`. Constant time.
    pub fn with_digest(rng: R, digest: D) -> Self {
        Self {
            rng,
            digest,
            settings: None,
        }
    }
}

impl<R, D: Digest + Display> DsaGroupGenerator<R, D> {
    /// BC's `Init(size, certainty, random)`: FIPS 186-2, p of `size` bits (512 to 1024, a
    /// multiple of 64) and q of 160, with SHA-1 as the digest. Stays uninitialized on failure.
    /// Variable time, only for public values.
    pub fn init_fips186_2(&mut self, size: u32, certainty: u32) -> Result<(), DsaError> {
        self.settings = None;
        if !(512..=1024).contains(&size) || size % 64 != 0 {
            return Err(DsaError::InvalidSize);
        }
        if self.digest.to_string() != "SHA-1" {
            return Err(DsaError::UnsuitableDigest);
        }
        if certainty == 0 {
            return Err(DsaError::InvalidCertainty);
        }
        self.settings = Some(Settings {
            l: size,
            n: 160,
            certainty,
            fips186_3: false,
            usage_index: None,
        });
        Ok(())
    }

    /// BC's `Init(DsaParameterGenerationParameters)`: FIPS 186-3, (L, N) one of (1024, 160),
    /// (2048, 224), (2048, 256) and (3072, 256), with a digest of at least N bits. Stays
    /// uninitialized on failure. Variable time, only for public values.
    pub fn init_fips186_3(&mut self, params: &DsaGroupGenerationParams) -> Result<(), DsaError> {
        self.settings = None;
        if !matches!(
            (params.l, params.n),
            (1024, 160) | (2048, 224) | (2048, 256) | (3072, 256)
        ) {
            return Err(DsaError::InvalidLengths);
        }
        if self.digest.digest_size() * 8 < params.n as usize {
            return Err(DsaError::UnsuitableDigest);
        }
        if params.certainty == 0 {
            return Err(DsaError::InvalidCertainty);
        }
        self.settings = Some(Settings {
            l: params.l,
            n: params.n,
            certainty: params.certainty,
            fips186_3: true,
            usage_index: params.usage_index,
        });
        Ok(())
    }
}

impl<R: CryptoRng, D: Digest + Display> DsaGroupGenerator<R, D> {
    /// BC's `GenerateParameters`: generates a group by the procedure `init` chose; an error
    /// before `init`. Variable time, only for public values: the group is public.
    pub fn generate_group(&mut self) -> Result<DsaParameters, DsaError> {
        let settings = self.settings.ok_or(DsaError::NotInitialized)?;
        Ok(if settings.fips186_3 {
            self.fips186_3(&settings)
        } else {
            self.fips186_2(&settings)
        })
    }

    /// Writes the hash of `input` into `output`. Variable time, only for public values: the
    /// seed is public.
    fn hash(&mut self, input: &[u8], output: &mut [u8]) {
        self.digest.update(input);
        self.digest.do_final(output);
    }

    /// BC's `GenerateParameters_FIPS186_2`. Variable time, only for public values.
    fn fips186_2(&mut self, settings: &Settings) -> DsaParameters {
        let l = settings.l as usize;
        let n = (l - 1) / 160;
        let mut seed = [0u8; 20];
        let (mut part1, mut part2) = ([0u8; 20], [0u8; 20]);
        let mut w = vec![0u8; l / 8];
        loop {
            self.rng.fill_bytes(&mut seed);
            self.hash(&seed, &mut part1);
            let mut next = seed;
            increment(&mut next);
            self.hash(&next, &mut part2);
            let mut u = [0u8; 20];
            for ((u, a), b) in u.iter_mut().zip(&part1).zip(&part2) {
                *u = a ^ b;
            }
            u[0] |= 0x80;
            u[19] |= 0x01;
            let q = big(&u);
            if !is_prime(&q, settings, &mut self.rng) {
                continue;
            }

            let mut offset = seed;
            increment(&mut offset);
            for counter in 0..4096u32 {
                for k in 0..n {
                    increment(&mut offset);
                    self.hash(&offset, &mut part1);
                    let end = w.len() - k * 20;
                    w[end - 20..end].copy_from_slice(&part1);
                }
                increment(&mut offset);
                self.hash(&offset, &mut part1);
                let rest = w.len() - n * 20;
                w[..rest].copy_from_slice(&part1[20 - rest..]);
                w[0] |= 0x80;
                if let Some(p) = candidate_p(&big(&w), &q, settings, &mut self.rng) {
                    let g = unverifiable_generator(&p, &q, &mut self.rng);
                    return parameters(
                        p,
                        q,
                        g,
                        DsaValidationParameters::new(seed.to_vec(), counter),
                    );
                }
            }
        }
    }

    /// BC's `GenerateParameters_FIPS186_3`. Variable time, only for public values.
    fn fips186_3(&mut self, settings: &Settings) -> DsaParameters {
        let (l, n) = (settings.l, settings.n);
        let outlen = self.digest.digest_size() * 8;
        let blocks = (l as usize - 1) / outlen;
        let tail = (l as usize - 1) % outlen;
        let mut seed = vec![0u8; n as usize / 8];
        let mut output = vec![0u8; self.digest.digest_size()];
        loop {
            self.rng.fill_bytes(&mut seed);
            self.hash(&seed, &mut output);
            let mut q = big(&output) % &power_of_two(n - 1);
            q.set_bit(0, true);
            q.set_bit(n - 1, true);
            if !is_prime(&q, settings, &mut self.rng) {
                continue;
            }

            let mut offset = seed.clone();
            for counter in 0..4 * l {
                let mut w = BigUint::from(0u8);
                for j in 0..=blocks {
                    increment(&mut offset);
                    self.hash(&offset, &mut output);
                    let mut v = big(&output);
                    if j == blocks {
                        v %= &power_of_two(tail as u32);
                    }
                    w += v << (j * outlen) as u32;
                }
                let mut x = w;
                x.set_bit(l - 1, true);
                let Some(p) = candidate_p(&x, &q, settings, &mut self.rng) else {
                    continue;
                };
                if let Some(index) = settings.usage_index {
                    if let Some(g) = self.verifiable_generator(&p, &q, &seed, index) {
                        let validation = DsaValidationParameters::new(seed.clone(), counter)
                            .with_usage_index(index);
                        return parameters(p, q, g, validation);
                    }
                }
                let g = unverifiable_generator(&p, &q, &mut self.rng);
                return parameters(p, q, g, DsaValidationParameters::new(seed.clone(), counter));
            }
        }
    }

    /// BC's `CalculateGenerator_FIPS186_3_Verifiable` (FIPS 186-3 A.2.3):
    /// W = H(seed ‖ "ggen" ‖ index ‖ count) and g = W^((p − 1) / q) mod p until g ≥ 2; `None`
    /// when 65535 tries fail. Variable time, only for public values.
    fn verifiable_generator(
        &mut self,
        p: &BigUint,
        q: &BigUint,
        seed: &[u8],
        index: u8,
    ) -> Option<BigUint> {
        let e = (p - 1u32) / q;
        let modulus = NonZero::new(p.clone())?;
        let mut u = [seed, b"ggen", &[index, 0, 0]].concat();
        let mut w = vec![0u8; self.digest.digest_size()];
        for _ in 1..(1u32 << 16) {
            increment(&mut u);
            self.hash(&u, &mut w);
            let g = big(&w).mod_pow(&e, &modulus);
            if g >= BigUint::from(2u8) {
                return Some(g);
            }
        }
        None
    }
}

/// X adjusted to p = X − (X mod 2q − 1), which must have exactly L bits and pass the primality
/// test. Variable time, only for public values.
fn candidate_p(
    x: &BigUint,
    q: &BigUint,
    settings: &Settings,
    rng: &mut dyn CryptoRng,
) -> Option<BigUint> {
    let c = x % &(q << 1u32);
    let p = x - &(c - 1u32);
    (p.bits() == settings.l && is_prime(&p, settings, rng)).then_some(p)
}

/// BC's `CalculateGenerator_FIPS186_2`, which is also the unverifiable way of FIPS 186-3: h
/// chosen uniformly in `[2, p − 2]` and g = h^((p − 1) / q) mod p until g > 1. h is drawn by
/// `random_range` of `tc_bigint`, which reads the random source otherwise than Bouncy Castle.
/// Variable time, only for public values.
fn unverifiable_generator(p: &BigUint, q: &BigUint, rng: &mut dyn CryptoRng) -> BigUint {
    let e = (p - 1u32) / q;
    let modulus = NonZero::new(p.clone()).expect("p is an odd prime");
    let low = PaddedBigUint::from(2u8);
    let high = PaddedBigUint::from(p - 1u32);
    loop {
        let h = BigUint::from(PaddedBigUint::random_range(&mut *rng, &low, &high));
        let g = h.mod_pow(&e, &modulus);
        if g.bits() > 1 {
            return g;
        }
    }
}

/// Tests as strongly as Bouncy Castle's `IsProbablePrime(certainty)`. Variable time, only for
/// public values: the candidates are public.
fn is_prime(candidate: &BigUint, settings: &Settings, rng: &mut dyn CryptoRng) -> bool {
    !candidate.has_small_factor()
        && candidate.is_probable_prime(rounds(settings.certainty, candidate.bits()), rng)
}

/// The Miller-Rabin rounds that test a randomly chosen candidate of `bits` bits to `certainty`,
/// as Bouncy Castle's `RabinMillerTest` works them out when `randomlySelected`. Variable time,
/// only for public values.
fn rounds(certainty: u32, bits: u32) -> u32 {
    let rounds = (certainty - 1) / 2 + 1;
    let for_certainty_100 = match bits {
        1024.. => 4,
        512.. => 8,
        256.. => 16,
        _ => 50,
    };
    if certainty < 100 {
        rounds.min(for_certainty_100)
    } else {
        rounds - 50 + for_certainty_100
    }
}

/// Puts the parameters together. Variable time, only for public values.
fn parameters(
    p: BigUint,
    q: BigUint,
    g: BigUint,
    validation: DsaValidationParameters,
) -> DsaParameters {
    DsaParameters::new(p.into(), q.into(), g.into()).with_validation(validation)
}

/// Big-endian bytes read as an integer. Variable time, only for public values.
fn big(bytes: &[u8]) -> BigUint {
    let Ok(value) = BigUint::from_be(bytes);
    value
}

/// 2^`bits`. Variable time, only for public values.
fn power_of_two(bits: u32) -> BigUint {
    let mut value = BigUint::from(0u8);
    value.set_bit(bits, true);
    value
}

/// BC's `Inc`: adds one to the bytes as a big-endian integer, wrapping on overflow. Variable
/// time, only for public values: the seed is public.
fn increment(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
