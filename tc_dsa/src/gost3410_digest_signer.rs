use crate::{Dsa, DsaDigestSignerError, DsaEncodingError, DsaInit};
use alloc::vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_signer::{Signer, SignerInit};

/// BC's `Gost3410DigestSigner`: the [`Signer`] the GOST signatures share, GOST R 34.10-94 and
/// 34.10-2001 and 2012. The message is hashed with `D` and the hash goes to `A` as it is (a GOST
/// DSA reads it as a little-endian integer); the signature is s ‖ r, each big-endian over the
/// length of the hash, unlike the encodings of [`DsaDigestSigner`](crate::DsaDigestSigner). Its
/// errors are [`DsaDigestSignerError`]s.
pub struct Gost3410DigestSigner<A, D> {
    dsa: A,
    digest: D,
    signing: Option<bool>,
}

impl<A, D> Gost3410DigestSigner<A, D> {
    /// BC's `Gost3410DigestSigner(signer, digest)`. Constant time.
    pub fn new(dsa: A, digest: D) -> Self {
        Self {
            dsa,
            digest,
            signing: None,
        }
    }
}

impl<A, D, P> SignerInit<P> for Gost3410DigestSigner<A, D>
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

impl<A, D> Signer for Gost3410DigestSigner<A, D>
where
    A: Dsa<Integer = PaddedBigUint>,
    D: Digest,
{
    type Error = DsaDigestSignerError<A::Error>;

    /// BC's `GetMaxSignatureSize`: twice the length of the hash. Constant time.
    fn max_signature_size(&self) -> usize {
        self.digest.digest_size() * 2
    }

    /// Adds `input` to the hash of the message; an error before `init`. Constant time as far as
    /// the digest is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.signing.ok_or(DsaDigestSignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// BC's `GenerateSignature`: finishes the hash, has the DSA sign it and writes s ‖ r.
    /// `ValueOutOfRange` when r or s does not fit the length of the hash, `OutputTooShort` when
    /// `output` is too short, and an error after `init` with a public key. Constant time as far
    /// as the DSA is; the layout handles only the public (r, s).
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForSigning);
        }
        let half = self.digest.digest_size();
        let mut hash = vec![0u8; half];
        self.digest.do_final(&mut hash);
        let (r, s) = self
            .dsa
            .generate_signature(&hash)
            .map_err(DsaDigestSignerError::Dsa)?;
        let output = output
            .get_mut(..half * 2)
            .ok_or(DsaDigestSignerError::Encoding(
                DsaEncodingError::OutputTooShort,
            ))?;
        let (first, second) = output.split_at_mut(half);
        write_be(&s, first)?;
        write_be(&r, second)?;
        Ok(half * 2)
    }

    /// BC's `VerifySignature`: the second half of the signature is r and the first s, which the
    /// DSA checks. A signature not twice the length of the hash, or that the DSA fails on, does
    /// not verify; Bouncy Castle throws on one too short and ignores the extra bytes of one too
    /// long. An error after `init` with a private key. Variable time, only for public values:
    /// the signature and the message are public.
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        if self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForVerifying);
        }
        let half = self.digest.digest_size();
        let mut hash = vec![0u8; half];
        self.digest.do_final(&mut hash);
        if signature.len() != half * 2 {
            return Ok(false);
        }
        let Ok(s) = PaddedBigUint::from_be(&signature[..half]);
        let Ok(r) = PaddedBigUint::from_be(&signature[half..]);
        Ok(self.dsa.verify_signature(&hash, &r, &s).unwrap_or(false))
    }

    /// Drops the message and keeps the key. Constant time.
    fn reset(&mut self) {
        self.digest.reset();
    }
}

/// Writes `value` big-endian over all of `output`, with leading zeros; `ValueOutOfRange` when
/// it does not fit, as Bouncy Castle's `AsUnsignedByteArray`. Variable time, only for public
/// values: it writes the public signature.
fn write_be<E>(value: &PaddedBigUint, output: &mut [u8]) -> Result<(), DsaDigestSignerError<E>> {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    let magnitude = &bytes[start..];
    if magnitude.len() > output.len() {
        return Err(DsaDigestSignerError::Encoding(
            DsaEncodingError::ValueOutOfRange,
        ));
    }
    output.fill(0);
    let offset = output.len() - magnitude.len();
    output[offset..].copy_from_slice(magnitude);
    Ok(())
}
