use crate::{DsaError, DsaValidationParameters};
use tc_bigint::PaddedBigUint;

// The default of Bouncy Castle's `DsaMaxSize`.
const MAX_MODULUS_BITS: u32 = 16384;

/// BC's `DsaParameters`: the modulus p, the subgroup order q, a generator g of order q, and the
/// optional validation data.
///
/// A container, not checked when it is built; the generators' and the signer's `init` call
/// [`validate`](Self::validate). Equality compares p, q and g alone, as Bouncy Castle's does.
#[derive(Clone, Debug)]
pub struct DsaParameters {
    p: PaddedBigUint,
    q: PaddedBigUint,
    g: PaddedBigUint,
    validation: Option<DsaValidationParameters>,
}

impl DsaParameters {
    /// p, q and g. Constant time.
    pub fn new(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            q,
            g,
            validation: None,
        }
    }

    /// Sets the validation data. Constant time.
    pub fn with_validation(mut self, validation: DsaValidationParameters) -> Self {
        self.validation = Some(validation);
        self
    }

    /// The modulus p. Constant time.
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// The subgroup order q. Constant time.
    pub fn q(&self) -> &PaddedBigUint {
        &self.q
    }

    /// The generator g. Constant time.
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// The validation data. Constant time.
    pub fn validation(&self) -> Option<&DsaValidationParameters> {
        self.validation.as_ref()
    }

    /// p has at most 16384 bits, checked first so that, as in Bouncy Castle, too large a modulus
    /// is turned down before any exponentiation; p is an odd number above 2; q is an odd number
    /// above 2 and below p; and g is in `[2, p − 1]`. Bouncy Castle checks the bound of p only for
    /// a public key; the rest are what the Montgomery arithmetic needs. Variable time, only for
    /// public values: the parameters are public.
    pub fn validate(&self) -> Result<(), DsaError> {
        if self.p.bits() > MAX_MODULUS_BITS {
            return Err(DsaError::ModulusTooLarge);
        }
        let two = PaddedBigUint::from(2u8);
        if !self.p.bit(0) || self.p <= two {
            return Err(DsaError::InvalidModulus);
        }
        if !self.q.bit(0) || self.q <= two || self.q >= self.p {
            return Err(DsaError::InvalidOrder);
        }
        if self.g < two || self.g >= self.p {
            return Err(DsaError::InvalidGenerator);
        }
        Ok(())
    }
}

impl PartialEq for DsaParameters {
    /// Compares p, q and g. Variable time, only for public values.
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p && self.q == other.q && self.g == other.g
    }
}

impl Eq for DsaParameters {}
