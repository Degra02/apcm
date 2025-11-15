use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY,
    traits::Identity,
};
use hex_literal::hex;
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

    fn is_canonical(encoded: &[u8; 32]) -> bool {
        let comp = CompressedEdwardsY(*encoded);
        match comp.decompress() {
            Some(p) => p.compress().to_bytes() == *encoded,
            None => false,
        }
    }

    fn get_blacklist() -> Vec<[u8; 32]> {
        let mut blacklist: Vec<[u8; 32]> = Vec::new();
        let identity = EdwardsPoint::identity().compress().to_bytes();
        blacklist.push(identity);
        let identity_non_canonical: [u8; 32] =
            hex!("0100000000000000000000000000000000000000000000000000000000000080");
        blacklist.push(identity_non_canonical);
        blacklist
    }

    fn get_blacklist_ver6() -> Vec<[u8; 32]> {
        vec![hex!(
            "0100000000000000000000000000000000000000000000000000000000000080"
        )]
    }

    fn is_blacklisted(encoded: &[u8; 32]) -> bool {
        Self::get_blacklist().iter().any(|b| b == encoded)
    }

    fn is_blacklisted_ver6(encoded: &[u8; 32]) -> bool {
        Self::get_blacklist_ver6().iter().any(|b| b == encoded)
    }

    fn has_torsion(point: &EdwardsPoint) -> bool {
        let identity = EdwardsPoint::identity();
        let factors = [1u64, 2, 4, 8];

        for &f in &factors {
            let scalar = Scalar::from(f);
            if point * scalar == identity {
                return true;
            }
        }

        false
    }

    pub(crate) fn verify(
        &self,
        m: &[u8],
        sig: &[u8; 64],
        mode: VerifyMode,
    ) -> Result<(), CustomError> {
        let r_bytes: [u8; 32] = sig[0..32]
            .try_into()
            .map_err(|_| CustomError::InvalidSignature)?;
        let s_bytes: [u8; 32] = sig[32..64]
            .try_into()
            .map_err(|_| CustomError::InvalidSignature)?;

        let r_comp = CompressedEdwardsY(r_bytes);
        let r_point = match r_comp.decompress() {
            Some(p) => p,
            None => return Err(CustomError::DecompressionError),
        };

        let s_scalar = Scalar::from_canonical_bytes(s_bytes)
            .into_option()
            .ok_or(CustomError::InvalidSignature)?;

        match mode {
            VerifyMode::Ver1Strict => {
                // reject non-canonical R
                if !Self::is_canonical(&r_bytes) {
                    return Err(CustomError::InvalidSignature);
                }

                // decode A and reject small order
                let a_point = self.point;
                if a_point.is_small_order() {
                    return Err(CustomError::InvalidPublicKey);
                }

                // k = H(R || A || M) using canonical R and A bytes
                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(self.compressed.as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }

            VerifyMode::Ver2NoSCanonicalCheck => {
                // reject non-canonical R only
                if !Self::is_canonical(&r_bytes) {
                    return Err(CustomError::InvalidSignature);
                }

                // decode A but do not check small or canonicalness
                let a_point = self.point;

                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(a_point.compress().as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }

            VerifyMode::Ver3NoRCanonicalCheck => {
                let a_point = self.point;
                let identity = EdwardsPoint::identity();
                let is_identity = a_point == identity;
                if !is_identity {
                    let a_bytes_arr: [u8; 32] = *self.compressed.as_bytes();
                    if !Self::is_canonical(&a_bytes_arr) {
                        return Err(CustomError::InvalidPublicKey);
                    }
                }

                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(a_point.compress().as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }

            VerifyMode::Ver4NoPublicKeyCheck => {
                if !Self::is_canonical(&r_bytes) {
                    return Err(CustomError::InvalidSignature);
                }

                let a_point = self.point;
                let identity = EdwardsPoint::identity();
                let is_identity = a_point == identity;
                if !is_identity {
                    let a_bytes_arr: [u8; 32] = *self.compressed.as_bytes();
                    if !Self::is_canonical(&a_bytes_arr) {
                        return Err(CustomError::InvalidPublicKey);
                    }
                }

                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(a_point.compress().as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }

            VerifyMode::Ver5AllowLowOrderR => {
                // VER5 rejects non-canonical A and blacklisted encodings
                let a_bytes_arr: [u8; 32] = *self.compressed.as_bytes();
                if !Self::is_canonical(&a_bytes_arr) {
                    return Err(CustomError::InvalidPublicKey);
                }

                if Self::is_blacklisted(&a_bytes_arr) {
                    return Err(CustomError::InvalidPublicKey);
                }

                // VER5 does not check R's blacklist
                let a_point = self.point;

                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(a_point.compress().as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }

            VerifyMode::Ver6Weak => {
                // VER6 rejects non-canonical A
                let a_bytes_arr: [u8; 32] = *self.compressed.as_bytes();
                if !Self::is_canonical(&a_bytes_arr) {
                    return Err(CustomError::InvalidPublicKey);
                }

                // VER6 rejects blacklisted A but only non-canonical identity
                if Self::is_blacklisted_ver6(&a_bytes_arr) {
                    return Err(CustomError::InvalidPublicKey);
                }

                let a_point = self.point;

                let mut hasher = sha2::Sha512::new();
                hasher.update(r_point.compress().as_bytes());
                hasher.update(a_point.compress().as_bytes());
                hasher.update(m);
                let k_scalar = Scalar::from_hash(hasher);

                let sb = s_scalar * ED25519_BASEPOINT_POINT;
                let r_ka = r_point + k_scalar * a_point;
                if sb == r_ka {
                    Ok(())
                } else {
                    Err(CustomError::InvalidSignature)
                }
            }
        }
    }
}
