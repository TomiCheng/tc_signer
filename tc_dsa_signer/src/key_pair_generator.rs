use crate::math::{naf_weight, random_in_range};
use crate::{DsaError, DsaKeyGenerationParams, DsaPrivateKey, DsaPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC's `DsaKeyPairGenerator`: x in `[1, q − 1]` with a NAF weight of at least a quarter of the
/// bit length of q, and y = g^x mod p. `init` checks the parameters and builds the Montgomery
/// parameters of p.
pub struct DsaKeyPairGenerator<R> {
    rng: R,
    state: Option<(DsaKeyGenerationParams, PaddedMontyParams)>,
}

impl<R> DsaKeyPairGenerator<R> {
    /// A generator that draws from `rng`, before `init`. Constant time.
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }
}

impl<R> KeyPairGeneratorInit<DsaKeyGenerationParams> for DsaKeyPairGenerator<R> {
    type Error = DsaError;

    /// Checks the parameters with [`DsaParameters::validate`](crate::DsaParameters::validate)
    /// and builds the Montgomery parameters of p. Variable time, only for public values: the
    /// parameters are public.
    fn init(&mut self, params: &DsaKeyGenerationParams) -> Result<(), DsaError> {
        self.state = None;
        params.params.validate()?;
        let p = Odd::new(params.params.p().clone()).ok_or(DsaError::InvalidModulus)?;
        self.state = Some((params.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for DsaKeyPairGenerator<R> {
    type PublicKey = DsaPublicKey;
    type PrivateKey = DsaPrivateKey;
    type Error = DsaError;

    /// BC's `GenerateKeyPair`: reads the random source as Bouncy Castle does, the bit length of
    /// q big-endian, discarding the candidates that do not qualify; y = g^x mod p. Constant time
    /// in x: neither the comparisons, the NAF weight nor the exponentiation branch on it, and
    /// discarded candidates are wiped; only how many are drawn shows, which has nothing to do
    /// with the x kept.
    fn generate_key_pair(&mut self) -> Result<(DsaPublicKey, DsaPrivateKey), DsaError> {
        let (params, monty) = self.state.as_mut().ok_or(DsaError::NotInitialized)?;
        let q = params.params.q();
        let one = PaddedBigUint::from(1u8);
        let high = q - 1u32;
        let min_weight = q.bits() >> 2;
        let x = loop {
            let mut x = random_in_range(&mut self.rng, &one, &high);
            if naf_weight(x.as_limbs()) >= min_weight {
                break x;
            }
            x.zeroize();
        };
        let power = Zeroizing::new(PaddedMontyForm::new(params.params.g(), monty).pow(&x));
        let y = power.retrieve();
        Ok((
            DsaPublicKey::new(y, params.params.clone()),
            DsaPrivateKey::new(x, params.params.clone()),
        ))
    }
}
