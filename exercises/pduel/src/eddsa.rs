use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use sha2::Digest;

use crate::utils::CustomError;

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
        hasher.update(&self.prefix);
        hasher.update(message);
        let r_scalar = Scalar::from_hash(hasher);

        let r_pint = &r_sca



    }
}

pub struct VerifyingKey {
    pub(crate) point: EdwardsPoint,
    pub(crate) compressed: CompressedEdwardsY,
}

impl VerifyingKey {
    pub fn from_scalar(scalar: &Scalar) -> Self {
        let point = scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let compressed = point.compress();
        VerifyingKey { point, compressed }
    }
}
