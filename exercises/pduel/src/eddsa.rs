use sha2::Digest;

pub struct SigningKey {
    pub(crate) secret_key: [u8; 32],
    pub(crate) verifying_key: Vec<u8>,
}

impl SigningKey {
    pub fn generate() -> Self {
        let secret_key = rand::random_iter::<u8>().take(32).collect::<Vec<u8>>();

        let hashed_key: [u8; 64] = sha2::Sha512::digest(&secret_key).into();
        let hashes_key = sha2::Sha512::default().chain_update(secret_key).finalize();
        let clamped_secred_key = {
            let mut key = hashed_key[..32].to_owned();
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            key
        };

        let scalar = u32::from_le_bytes([
            clamped_secred_key[0],
            clamped_secred_key[1],
            clamped_secred_key[2],
            clamped_secred_key[3],
        ]);


    }
}
