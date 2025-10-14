mod chacha20;

// Author: Filippo De Grandi
// Group: Bachata20
//
// How to run tests:
// cargo test <test-name> -- --nocapture
//
// How to run solution:
// cargo test solution -- --nocapture
//
// this will print the keystream

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use crate::chacha20::{ChaCha20, InvalidLength, Output};

    #[test]
    fn solution() -> Result<(), InvalidLength> {
        let key = hex!("330146455a0009591655451707015e12000e59150d0b4d474453541412000000");
        let nonce = b"Fencing or D";
        let counter = b"Ex_0";
        let constant = b"DanceOfRaloberon";

        let mut cipher = ChaCha20::new(key.as_ref(), nonce, Some(u32::from_le_bytes(*counter)), Some(constant))?;
        let keystream = Output(cipher.keystream(128));

        println!("Keystream: {}", keystream);

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

    #[test]
    fn rfc_kat() -> Result<(), InvalidLength> {
        let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex!("000000000000004a00000000");
        let counter = 1u32;

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut cipher = ChaCha20::new(&key, &nonce, Some(counter), None)?;
        let output = cipher.encrypt(plaintext);
        let expected_ciphertext = hex!("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");

        assert_eq!(output.as_bytes(), &expected_ciphertext);

        Ok(())
    }
}
