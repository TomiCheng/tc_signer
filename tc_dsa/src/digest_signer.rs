use crate::{Dsa, DsaDigestSignerError, DsaEncoding, DsaInit, StandardDsaEncoding};
use alloc::vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_signer::{Signer, SignerInit};

/// BC's `DsaDigestSigner`: a [`Dsa`], which signs a hash, as a [`Signer`] of `tc_signer`. The
/// message is hashed with `D`, signed by `A` as (r, s) and encoded with `N`, by default the DER
/// of [`StandardDsaEncoding`].
///
/// The crates that implement [`Dsa`] show it in use: they depend on this one, so the examples
/// cannot live here.
pub struct DsaDigestSigner<A, D, N = StandardDsaEncoding> {
    dsa: A,
    digest: D,
    encoding: N,
    signing: Option<bool>,
}

impl<A, D> DsaDigestSigner<A, D> {
    /// BC's `DsaDigestSigner(dsa, digest)`: signatures in DER. Constant time.
    pub fn new(dsa: A, digest: D) -> Self {
        Self::with_encoding(dsa, digest, StandardDsaEncoding)
    }
}

impl<A, D, N> DsaDigestSigner<A, D, N> {
    /// BC's `DsaDigestSigner(dsa, digest, encoding)`, as with
    /// [`PlainDsaEncoding`](crate::PlainDsaEncoding). Constant time.
    pub fn with_encoding(dsa: A, digest: D, encoding: N) -> Self {
        Self {
            dsa,
            digest,
            encoding,
            signing: None,
        }
    }
}

impl<A, D, N, P> SignerInit<P> for DsaDigestSigner<A, D, N>
where
    A: DsaInit<P>,
    D: Digest,
    P: AsymmetricKeyParams + ?Sized,
{
    type Error = DsaDigestSignerError<<A as DsaInit<P>>::Error>;

    /// BC's `Init`: a private key signs and a public key verifies. Starts a new message and keys
    /// the DSA underneath, staying uninitialized if that fails. Constant time as far as the
    /// DSA's `init` is.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.signing = None;
        self.digest.reset();
        self.dsa.init(params).map_err(DsaDigestSignerError::Dsa)?;
        self.signing = Some(params.is_private_key());
        Ok(())
    }
}

impl<A, D, N> Signer for DsaDigestSigner<A, D, N>
where
    A: Dsa<Integer = PaddedBigUint>,
    D: Digest,
    N: DsaEncoding,
{
    type Error = DsaDigestSignerError<A::Error>;

    /// The most bytes the encoding takes for the group order. Panics before `init`. Variable
    /// time, only for public values: the order is public.
    fn max_signature_size(&self) -> usize {
        self.encoding.max_encoding_size(self.dsa.order())
    }

    /// Adds `input` to the hash of the message; an error before `init`. Constant time as far as
    /// the digest is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.signing.ok_or(DsaDigestSignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// BC's `GenerateSignature`: finishes the hash, has the DSA sign it and encodes (r, s) into
    /// `output`; an error after `init` with a public key. Constant time as far as the DSA is;
    /// the encoding handles only the public (r, s).
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForSigning);
        }
        let mut hash = vec![0u8; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        let (r, s) = self
            .dsa
            .generate_signature(&hash)
            .map_err(DsaDigestSignerError::Dsa)?;
        self.encoding
            .encode(self.dsa.order(), &r, &s, output)
            .map_err(DsaDigestSignerError::Encoding)
    }

    /// BC's `VerifySignature`: reads (r, s) and has the DSA check it; a signature that does not
    /// decode, or that the DSA fails on, does not verify, as in Bouncy Castle. An error after
    /// `init` with a private key. Variable time, only for public values: the signature and the
    /// message are public.
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        if self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForVerifying);
        }
        let mut hash = vec![0u8; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        let Ok((r, s)) = self.encoding.decode(self.dsa.order(), signature) else {
            return Ok(false);
        };
        Ok(self.dsa.verify_signature(&hash, &r, &s).unwrap_or(false))
    }

    /// Drops the message and keeps the key. Constant time.
    fn reset(&mut self) {
        self.digest.reset();
    }
}
