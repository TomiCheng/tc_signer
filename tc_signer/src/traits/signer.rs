//! Signing and verifying a message in pieces.

/// An initialized signer, the Rust form of Bouncy Castle's `ISigner`: it takes
/// a message in pieces and signs it, or verifies a signature over it.
///
/// The key given to [`SignerInit`] decides which: a private key signs and a
/// public key verifies. The signer hashes and encodes the message itself, so
/// a caller passes the message as it is, not a digest of it.
///
/// The signature is written into a caller-provided buffer, so the contract
/// requires neither `alloc` nor `std`. Implementations with the same
/// [`Error`](Signer::Error) type can be stored behind
/// `dyn Signer<Error = E>` after initialization.
pub trait Signer {
    /// The failure type, such as signing with a public key.
    type Error: core::error::Error;

    /// Returns the most bytes a signature takes, Bouncy Castle's
    /// `GetMaxSignatureSize`, the size of the buffer that
    /// [`generate_signature`](Self::generate_signature) needs. Some signers
    /// learn it from the key, and may panic before `init`.
    fn max_signature_size(&self) -> usize;

    /// Adds `input` to the message. Fails before `init`.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Signs the message into the front of `output` and returns the length
    /// of the signature, which can vary, as a DER one does. The next message
    /// starts empty, under the same key.
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns whether `signature` is a signature of the message. A signature
    /// that does not verify is `Ok(false)`, not an error. The next message
    /// starts empty, under the same key.
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error>;

    /// Discards the message and keeps the key.
    fn reset(&mut self);
}

/// Initializes a signer from parameters of type `P`: a private key to sign, a
/// public key to verify.
///
/// This trait is independent of [`Signer`]. A signer implements it once for
/// each key type it accepts, and a consumer that needs both capabilities uses
/// `S: Signer + SignerInit<P>`.
pub trait SignerInit<P: ?Sized> {
    /// The failure type, such as a key of the wrong size.
    type Error: core::error::Error;

    /// Takes the key and starts a new message.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
