use crate::DsaSignerError;
use crate::{DsaPrivateKey, DsaPublicKey};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_modular::{ModAdd, ModInverse, ModMul, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC's `DsaSigner`: the DSA of FIPS 186. r = (g^k mod p) mod q and s = k⁻¹ · (m + x·r) mod q,
/// m the first ⌊bits(q) / 8⌋ bytes of the hash. `K` gives k: the random `RandomDsaKCalculator`
/// or RFC 6979's `HMacDsaKCalculator`. When r or s is zero another k is drawn, as FIPS 186-4 4.6
/// asks; Bouncy Castle does not draw again.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
/// use tc_dsa_signer::{
///     DsaGroupGenerationParams, DsaGroupGenerator, DsaKeyGenerationParams, DsaKeyPairGenerator,
///     DsaSigner,
/// };
/// use tc_sha::Sha256Digest;
///
/// // A group of FIPS 186-3; in practice a published group serves, with no need to generate one.
/// let mut generator = DsaGroupGenerator::with_digest(rand::rng(), Sha256Digest::new());
/// generator.init_fips186_3(&DsaGroupGenerationParams::new(2048, 256, 80))?;
/// let params = generator.generate_group()?;
///
/// let mut rng = rand::rng();
/// let mut keys = DsaKeyPairGenerator::new(&mut rng);
/// keys.init(&DsaKeyGenerationParams::new(params))?;
/// let (public_key, private_key) = keys.generate_key_pair()?;
///
/// // Sign the hash of a message with RFC 6979's deterministic k.
/// let hash = [0x42; 32];
/// let mut signer = DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
/// signer.init(&private_key)?;
/// let (r, s) = signer.generate_signature(&hash)?;
///
/// let mut verifier = DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
/// verifier.init(&public_key)?;
/// assert!(verifier.verify_signature(&hash, &r, &s)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DsaSigner<K> {
    k_calculator: K,
    state: Option<State>,
}

/// What `init` keeps: the key, the Montgomery parameters of p, and q.
struct State {
    key: Key,
    monty: PaddedMontyParams,
    q: NonZero<PaddedBigUint>,
}

/// A private key to sign, or a public key to verify.
enum Key {
    Private(DsaPrivateKey),
    Public(DsaPublicKey),
}

impl<K> DsaSigner<K> {
    /// A signer that takes k from `k_calculator`, before `init`. Constant time.
    pub fn new(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    /// Builds the Montgomery parameters of p and keeps q and the key. Variable time, only for
    /// public values: it reads the public parameters alone.
    fn start(
        &mut self,
        key: Key,
        p: &PaddedBigUint,
        q: &PaddedBigUint,
    ) -> Result<(), DsaSignerError> {
        let p = Odd::new(p.clone())
            .ok_or(DsaSignerError::InvalidKey(crate::DsaError::InvalidModulus))?;
        let q = NonZero::new(q.clone())
            .ok_or(DsaSignerError::InvalidKey(crate::DsaError::InvalidOrder))?;
        self.state = Some(State {
            key,
            monty: PaddedMontyParams::new(p),
            q,
        });
        Ok(())
    }
}

/// BC's `CalculateE`: the first ⌊bits(q) / 8⌋ bytes of `message` read as a big-endian integer.
/// Constant time: only the lengths decide.
fn calculate_e(q: &PaddedBigUint, message: &[u8]) -> PaddedBigUint {
    let length = message.len().min(q.bits() as usize / 8);
    let Ok(e) = PaddedBigUint::from_be(&message[..length]);
    e
}

impl<K> DsaInit<DsaPrivateKey> for DsaSigner<K> {
    type Error = DsaSignerError;

    /// Checks the key with [`DsaPrivateKey::validate`] and keeps a copy, whose x is wiped on
    /// drop; stays uninitialized if that fails. Constant time in x: the range check shows only
    /// whether it passes, and the parameters are checked as public values.
    fn init(&mut self, key: &DsaPrivateKey) -> Result<(), DsaSignerError> {
        self.state = None;
        key.validate().map_err(DsaSignerError::InvalidKey)?;
        let params = key.params();
        self.start(Key::Private(key.clone()), params.p(), params.q())
    }
}

impl<K> DsaInit<DsaPublicKey> for DsaSigner<K> {
    type Error = DsaSignerError;

    /// Checks the key with [`DsaPublicKey::validate`] and keeps a copy; stays uninitialized if
    /// that fails. Variable time, only for public values.
    fn init(&mut self, key: &DsaPublicKey) -> Result<(), DsaSignerError> {
        self.state = None;
        key.validate().map_err(DsaSignerError::InvalidKey)?;
        let params = key.params();
        self.start(Key::Public(key.clone()), params.p(), params.q())
    }
}

impl<K: DsaKCalculator<PaddedBigUint>> Dsa for DsaSigner<K> {
    type Integer = PaddedBigUint;
    type Error = DsaSignerError;

    /// The subgroup order q. Panics before `init`. Constant time.
    fn order(&self) -> &PaddedBigUint {
        &self.state.as_ref().expect("the signer is initialized").q
    }

    /// BC's `GenerateSignature`: the k calculator gives k from q, x and `message`, and another
    /// k is taken when r or s is zero. An error after `init` with a public key. Constant time in
    /// x and k: the exponentiation, the modular products and sum and the inverse are; only how
    /// many k are taken shows, which has nothing to do with the last one.
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaSignerError> {
        let state = self.state.as_ref().ok_or(DsaSignerError::NotInitialized)?;
        let Key::Private(key) = &state.key else {
            return Err(DsaSignerError::NotForSigning);
        };
        let q = &state.q;
        let zero = PaddedBigUint::from(0u8);
        let m = calculate_e(q, message) % &**q;
        let x = key.x();
        self.k_calculator.init(q, x, message);
        loop {
            let k = Zeroizing::new(self.k_calculator.next_k());
            let power =
                Zeroizing::new(PaddedMontyForm::new(key.params().g(), &state.monty).pow(&k));
            let r = power.retrieve() % &**q;
            if r == zero {
                continue;
            }
            let inverse = Zeroizing::new(k.mod_inverse(q).expect("k lies in [1, q - 1]"));
            let product = Zeroizing::new(x.mod_mul(&r, q));
            let sum = Zeroizing::new(product.mod_add(&m, q));
            let s = inverse.mod_mul(&sum, q);
            if s != zero {
                return Ok((r, s));
            }
        }
    }

    /// BC's `VerifySignature`: r and s must be in `[1, q − 1]`, w = s⁻¹, and
    /// v = (g^(m·w) · y^(r·w) mod p) mod q must equal r. An error after `init` with a private
    /// key. Variable time, only for public values: the signature and the message are public.
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, DsaSignerError> {
        let state = self.state.as_ref().ok_or(DsaSignerError::NotInitialized)?;
        let Key::Public(key) = &state.key else {
            return Err(DsaSignerError::NotForVerifying);
        };
        let q = &state.q;
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || r >= &**q || *s == zero || s >= &**q {
            return Ok(false);
        }
        let m = calculate_e(q, message);
        let Some(w) = s.mod_inverse(q) else {
            return Ok(false);
        };
        let u1 = m.mod_mul(&w, q);
        let u2 = r.mod_mul(&w, q);
        let mut v = PaddedMontyForm::new(key.params().g(), &state.monty).pow(&u1);
        v *= &PaddedMontyForm::new(key.y(), &state.monty).pow(&u2);
        Ok(v.retrieve() % &**q == *r)
    }
}
