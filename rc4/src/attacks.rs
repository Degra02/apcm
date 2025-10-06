use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rc4::{Output, RC4};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RC4Attack {
    #[zeroize]
    rc4: RC4,

    #[zeroize]
    key: Vec<u8>,
}

impl RC4Attack {
    pub fn new(key: &[u8]) -> Self {
        let rc4 = RC4::new(key).unwrap();

        Self {
            rc4,
            key: key.to_vec(),
        }
    }

    fn encrypt(&mut self, plaintext: &str) -> Vec<u8> {
        self.rc4.encrypt(plaintext.as_bytes()).as_bytes().to_vec()
    }

    pub fn malleability(&mut self, modified_plaintext: &str) -> Output {
        let original_plaintext = "We shall attack all intruders ";
        let original_ciphertext = self.encrypt(original_plaintext);


        let mut forged_ciphertext = original_ciphertext.clone();

        for (i, forged_cipher_i) in forged_ciphertext.iter_mut().enumerate().take(original_plaintext.len()) {
            *forged_cipher_i ^= original_plaintext.as_bytes()[i] ^ modified_plaintext.as_bytes()[i];
        }

        Output(forged_ciphertext)
    }
}
