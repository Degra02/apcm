use curve25519_dalek::Scalar;
use sha2::Digest;

pub struct SigningKey {
    pub(crate) secret_key: [u8; 32],
    pub(crate) verifying_key: [u8; 32],
}

impl SigningKey {
    pub fn generate(seed: &[u8; 32]) -> Self {
        let digest = sha2::Sha512::digest(seed);
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&digest[0..32]);

        secret_key[0] &= 248;
        secret_key[31] &= 63;
        secret_key[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(secret_key);

        let verifying_key = (scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        SigningKey {
            secret_key,
            verifying_key,
        }
    }
}
