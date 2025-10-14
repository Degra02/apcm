mod chacha20;

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::chacha20::{ChaCha20, InvalidLength};

    #[test]
    fn solution() -> Result<(), InvalidLength> {
        let key = hex!("330146455a0009591655451707015e12000e59150d0b4d474453541412000000");
        let nonce = b"Fencing or D";
        let counter = b"Ex_0";
        let constant = b"DanceOfRaloberon";
        
        println!("Key: {:x?}, Len: {}", key, key.len());

        let mut cipher = ChaCha20::new(key.as_ref(), nonce.as_ref(), Some(counter), Some(constant));

        Ok(())
    }

    #[test]
    fn implementation() -> Result<(), InvalidLength> {
        let key = [0x42; 32];
        let nonce = [0x24; 12];
        let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
        let ciphertext = hex!("e405626e 4f1236b3 670ee428 332ea20e");

        let mut cipher = ChaCha20::new(&key, &nonce, None, None)?;

        let output = cipher.encrypt(&plaintext);


        assert_eq!(output.as_bytes(), &ciphertext);
        Ok(())
    }

}
