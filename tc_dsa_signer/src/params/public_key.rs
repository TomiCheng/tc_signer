use crate::{DsaError, DsaParameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_modular::{ModPow, NonZero};

/// BC's `DsaPublicKeyParameters`: the public value y = g^x mod p with its parameters. A
/// container; [`validate`](Self::validate) runs the checks of Bouncy Castle's constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPublicKey {
    y: PaddedBigUint,
    params: DsaParameters,
}

impl DsaPublicKey {
    /// Holds y and the parameters, unchecked. Constant time.
    pub fn new(y: PaddedBigUint, params: DsaParameters) -> Self {
        Self { y, params }
    }

    /// The public value y. Constant time.
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// BC's `Validate`: the parameters pass their checks, y is in `[2, p − 2]` and
    /// y^q ≡ 1 (mod p). Variable time, only for public values.
    pub fn validate(&self) -> Result<(), DsaError> {
        self.params.validate()?;
        let p = self.params.p();
        if self.y < PaddedBigUint::from(2u8) || self.y > p - 2u32 {
            return Err(DsaError::InvalidPublicKey);
        }
        let modulus = NonZero::new(p.clone()).ok_or(DsaError::InvalidModulus)?;
        if self.y.mod_pow(self.params.q(), &modulus) != PaddedBigUint::from(1u8) {
            return Err(DsaError::InvalidPublicKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for DsaPublicKey {
    /// A public key. Constant time.
    fn is_private_key(&self) -> bool {
        false
    }
}
