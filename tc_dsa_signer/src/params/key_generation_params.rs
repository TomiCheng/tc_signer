use crate::DsaParameters;

/// BC's `DsaKeyGenerationParameters` without the random source, which the generator takes when
/// it is constructed.
#[derive(Clone)]
pub struct DsaKeyGenerationParams {
    pub(crate) params: DsaParameters,
}

impl DsaKeyGenerationParams {
    /// Holds the parameters, which the generator's `init` checks. Constant time.
    pub fn new(params: DsaParameters) -> Self {
        Self { params }
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// BC's `Strength`: the bit length of p less one. Constant time.
    pub fn strength(&self) -> u32 {
        self.params.p().bits().saturating_sub(1)
    }
}
