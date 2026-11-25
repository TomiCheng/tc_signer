use alloc::vec::Vec;

/// BC's `DsaValidationParameters`: the seed and counter p and q were generated from, and the
/// usage index when g was generated verifiably as FIPS 186-3 has it. Equality compares the seed
/// and the counter alone, as Bouncy Castle's does.
#[derive(Clone, Debug)]
pub struct DsaValidationParameters {
    seed: Vec<u8>,
    counter: u32,
    usage_index: Option<u8>,
}

impl DsaValidationParameters {
    /// The seed and the counter, with no usage index. Constant time.
    pub fn new(seed: Vec<u8>, counter: u32) -> Self {
        Self {
            seed,
            counter,
            usage_index: None,
        }
    }

    /// Sets the usage index. Constant time.
    pub fn with_usage_index(mut self, usage_index: u8) -> Self {
        self.usage_index = Some(usage_index);
        self
    }

    /// The seed. Constant time.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// The counter. Constant time.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// The usage index; `None` when there is none, Bouncy Castle's −1. Constant time.
    pub fn usage_index(&self) -> Option<u8> {
        self.usage_index
    }
}

impl PartialEq for DsaValidationParameters {
    /// Compares the seed and the counter. Variable time, only for public values.
    fn eq(&self, other: &Self) -> bool {
        self.counter == other.counter && self.seed == other.seed
    }
}

impl Eq for DsaValidationParameters {}
