use crate::rc4::{Output, RC4};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RC4Attack {
    #[zeroize]
    rc4: RC4,

    #[zeroize]
    key: Vec<u8>,
}

impl RC4Attack {
    pub fn new(rc4: RC4, key: &[u8]) -> Self {
        Self {
            rc4,
            key: key.to_vec(),
        }
    }

    /// Given the original ciphertext, the original plaintext and the modified plaintext,
    /// it forges a new ciphertext that will decrypt to the modified plaintext.
    ///
    /// # Arguments
    /// * `original_ciphertext` - The original ciphertext.
    /// * `original_plaintext` - The original plaintext.
    /// * `modified_plaintext` - The desired modified plaintext.
    ///
    /// # Returns
    /// An [Output] ciphertext that will decrypt to the modified plaintext.
    pub fn malleability(
        &mut self,
        original_ciphertext: &[u8],
        original_plaintext: &str,
        modified_plaintext: &str,
    ) -> Output {
        let mut forged_ciphertext = original_ciphertext.to_vec();

        for (i, forged_cipher_i) in forged_ciphertext
            .iter_mut()
            .enumerate()
            .take(original_plaintext.len())
        {
            *forged_cipher_i ^= original_plaintext.as_bytes()[i] ^ modified_plaintext.as_bytes()[i];
        }

        Output(forged_ciphertext)
    }

    /// Recovers the keystream used to encrypt the given plaintext into the given ciphertext,
    /// up to the length of the plaintext.
    ///
    /// # Arguments
    /// * `plaintext` - The known plaintext.
    /// * `ciphertext` - The corresponding ciphertext.
    ///
    /// # Returns
    /// A [Vec<u8>] containing the recovered keystream.
    pub fn recover_key_stream(&mut self, plaintext: &str, ciphertext: &[u8]) -> Vec<u8> {
        let mut keystream = vec![];

        for (i, &cipher_i) in ciphertext.iter().enumerate().take(plaintext.len()) {
            keystream.push(cipher_i ^ plaintext.as_bytes()[i]);
        }

        keystream
    }
}
