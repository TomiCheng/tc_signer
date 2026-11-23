//! Signatures that carry part of the message.

use crate::Signer;

/// A signer that recovers part or all of the message from the signature, the
/// Rust form of Bouncy Castle's `ISignerWithRecovery`, as ISO/IEC 9796-2 does.
///
/// Such a signature holds as much of the message as fits in it, and a verifier
/// reads that part back; the rest of the message travels on its own. Before
/// verifying, a verifier feeds the signature to
/// [`update_with_recovered_message`](Self::update_with_recovered_message) and
/// then updates with the rest of the message only.
pub trait SignerWithRecovery: Signer {
    /// Returns whether the last verification recovered the whole message,
    /// Bouncy Castle's `HasFullMessage`, so that none of it travels on its
    /// own.
    fn has_full_message(&self) -> bool;

    /// Returns the message recovered by the last verification or by
    /// [`update_with_recovered_message`](Self::update_with_recovered_message),
    /// if any, Bouncy Castle's `GetRecoveredMessage`.
    fn recovered_message(&self) -> Option<&[u8]>;

    /// Recovers the part of the message that `signature` holds and feeds it
    /// to the signer, Bouncy Castle's `UpdateWithRecoveredMessage`, so that
    /// later updates carry only the rest of the message. It comes before any
    /// update. Fails on a signature that does not decode.
    fn update_with_recovered_message(&mut self, signature: &[u8]) -> Result<(), Self::Error>;
}
