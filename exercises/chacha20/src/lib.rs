mod chacha20;

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::chacha20::{ChaCha20, InvalidLength};

    #[test]
    fn solution() {
        let key = b"";
        let nonce = b"Fencing or Dance";
        let counter = b"Ex_04_01";

    }

    #[test]
    fn implementation() -> Result<(), InvalidLength> {
        let key = [0x42; 32];
        let nonce = [0x24; 12];
        let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
        let ciphertext = hex!("e405626e 4f1236b3 670ee428 332ea20e");

        let mut cipher = ChaCha20::new(&key, &nonce, None)?;

        let output = cipher.encrypt(&plaintext);


        assert_eq!(output.as_bytes(), &ciphertext);
        Ok(())
    }

}
