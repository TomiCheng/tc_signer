/// BC's `DsaParameterGenerationParameters` without the random source, which the generator takes
/// when it is constructed, named after `DhGroupGenerationParams` of `tc_dh_key`: the bit lengths L
/// of p and N of q of FIPS 186-3 and the certainty of the primality tests. With a usage index, g
/// is generated verifiably as FIPS 186-3 A.2.3 has it. A container; the generator's `init` checks
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DsaGroupGenerationParams {
    pub(crate) l: u32,
    pub(crate) n: u32,
    pub(crate) certainty: u32,
    pub(crate) usage_index: Option<u8>,
}

impl DsaGroupGenerationParams {
    /// Bouncy Castle's `DigitalSignatureUsage`.
    pub const DIGITAL_SIGNATURE_USAGE: u8 = 1;
    /// Bouncy Castle's `KeyEstablishmentUsage`.
    pub const KEY_ESTABLISHMENT_USAGE: u8 = 2;

    /// No usage index: g is generated at random. Constant time.
    pub fn new(l: u32, n: u32, certainty: u32) -> Self {
        Self {
            l,
            n,
            certainty,
            usage_index: None,
        }
    }

    /// Sets the usage index, so that g is generated verifiably. Constant time.
    pub fn with_usage_index(mut self, usage_index: u8) -> Self {
        self.usage_index = Some(usage_index);
        self
    }

    /// L. Constant time.
    pub fn l(&self) -> u32 {
        self.l
    }

    /// N. Constant time.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// The certainty. Constant time.
    pub fn certainty(&self) -> u32 {
        self.certainty
    }

    /// The usage index. Constant time.
    pub fn usage_index(&self) -> Option<u8> {
        self.usage_index
    }
}
