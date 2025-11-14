use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, traits::Identity,
    EdwardsPoint, Scalar,
};
use sha2::Digest;
use strum::EnumIter;

use crate::utils::CustomError;

#[derive(Debug)]
pub struct SigningKey {
    pub(crate) seed: [u8; 32],
    pub(crate) scalar: Scalar,
    pub(crate) prefix: [u8; 32],
    pub(crate) verifying_key: VerifyingKey,
}

impl SigningKey {
    pub fn generate(seed: &[u8; 32]) -> Self {
        let digest = sha2::Sha512::digest(seed);

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&digest[0..32]);
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 63;
        scalar_bytes[31] |= 64;

        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&digest[32..64]);

        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let verifying_key = VerifyingKey::from_scalar(&scalar);

        SigningKey {
            seed: *seed,
            scalar,
            prefix,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut hasher = sha2::Sha512::new();
        hasher.update(self.prefix);
        hasher.update(message);
        let r_scalar = Scalar::from_hash(hasher);

        let r_point = &r_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let r_compressed = r_point.compress();

        let mut hasher = sha2::Sha512::new();
        hasher.update(r_compressed.as_bytes());
        hasher.update(self.verifying_key.compressed.as_bytes());
        hasher.update(message);
        let k_scalar = Scalar::from_hash(hasher);

        let s_scalar = r_scalar + k_scalar * self.scalar;

        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(r_compressed.as_bytes());
        signature[32..64].copy_from_slice(&s_scalar.to_bytes());
        signature
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8; 64],
        mode: VerifyMode,
    ) -> Result<(), CustomError> {
        self.verifying_key.verify(message, signature, mode)
    }
}

#[derive(Debug, EnumIter)]
pub enum VerifyMode {
    Ver1Strict,
    Ver2NoSCanonicalCheck,
    Ver3NoRCanonicalCheck,
    Ver4NoPublicKeyCheck,
    Ver5AllowLowOrderR,
    Ver6Weak,
}

#[derive(Debug)]
pub struct VerifyingKey {
    pub(crate) point: EdwardsPoint,
    pub(crate) compressed: CompressedEdwardsY,
}

impl VerifyingKey {
    pub(crate) fn from_scalar(scalar: &Scalar) -> Self {
        let point = scalar * ED25519_BASEPOINT_POINT;
        let compressed = point.compress();
        VerifyingKey { point, compressed }
    }

    pub(crate) fn verify(
        &self,
        m: &[u8],
        sig: &[u8; 64],
        mode: VerifyMode,
    ) -> Result<(), CustomError> {
        let r_bytes = &sig[..32];
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..]);

        let r_point = match CompressedEdwardsY::from_slice(r_bytes)?.decompress() {
            Some(r) => r,
            None => {
                match mode {
                    VerifyMode::Ver3NoRCanonicalCheck | VerifyMode::Ver6Weak => {
                        // this is skipping decompression failure
                        EdwardsPoint::identity()
                    }
                    _ => return Err(CustomError::DecompressionError),
                }
            }
        };

        let s_scalar = Scalar::from_bytes_mod_order(s_bytes);

        if !matches!(
            mode,
            VerifyMode::Ver2NoSCanonicalCheck | VerifyMode::Ver6Weak
        ) && Scalar::from_canonical_bytes(s_bytes).is_none().into()
        {
            // S is not canonical
            return Err(CustomError::NonCanonicalS);
        }

        if !matches!(
            mode,
            VerifyMode::Ver4NoPublicKeyCheck | VerifyMode::Ver6Weak
        ) && self.point.is_small_order()
        {
            // A' is low order
            return Err(CustomError::InvalidPublicKey);
        }

        if !matches!(mode, VerifyMode::Ver5AllowLowOrderR | VerifyMode::Ver6Weak)
            && r_point.is_small_order()
        {
            // R is low order
            return Err(CustomError::InvalidSignature);
        }

        // SHA512(R || A || M)
        let mut hasher = sha2::Sha512::new();
        hasher.update(r_bytes);
        hasher.update(self.compressed.as_bytes());
        hasher.update(m);

        let k_scalar = Scalar::from_hash(hasher);

        // Check [S]B = R + [k]A'
        let sb = s_scalar * ED25519_BASEPOINT_POINT;
        let r_ka = r_point + k_scalar * self.point;

        match sb == r_ka {
            true => Ok(()),
            false => Err(CustomError::InvalidSignature),
        }
    }
}
