use crate::{DsaError, DsaParameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// BC's `DsaPrivateKeyParameters`: the private value x with its parameters, x wiped on drop. A
/// container; [`validate`](Self::validate) checks the range, which Bouncy Castle does not.
///
/// It has no `Debug` or `PartialEq`, so that x is neither printed nor compared in variable time.
#[derive(Clone)]
pub struct DsaPrivateKey {
    x: PaddedBigUint,
    params: DsaParameters,
}

impl DsaPrivateKey {
    /// Holds x and the parameters, unchecked. Constant time.
    pub fn new(x: PaddedBigUint, params: DsaParameters) -> Self {
        Self { x, params }
    }

    /// The private value x. Constant time.
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// The parameters pass their checks and x is in `[1, q − 1]`. Constant time in x: it shows
    /// only whether the check passes; the parameters are checked as public values.
    pub fn validate(&self) -> Result<(), DsaError> {
        self.params.validate()?;
        if self.x < PaddedBigUint::from(1u8) || &self.x >= self.params.q() {
            return Err(DsaError::InvalidPrivateKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for DsaPrivateKey {
    /// A private key. Constant time.
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for DsaPrivateKey {
    /// Wipes x. Constant time.
    fn drop(&mut self) {
        self.x.zeroize();
    }
}
