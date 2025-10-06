pub mod attacks;
pub mod rc4;

#[cfg(test)]
mod tests {
    use crate::{attacks::RC4Attack, rc4::RC4};

    #[test]
    fn malleability_attack() {
        let key = "cicciopasticcio";
        let mut attack = RC4Attack::new(key.as_ref());

        let modified_plaintext = "We shall kiss & hug intruders ";
        let forged_ciphertext = attack.malleability(modified_plaintext);

        let decrypted_forged = RC4::decrypt(key.as_ref(), forged_ciphertext.as_bytes())
            .to_utf8()
            .unwrap();
        println!("forged ciphertext: {forged_ciphertext}");
        println!("forged ciphertext decrypts to: {decrypted_forged}");
    }

    #[test]
    fn rc4_impl() {
        let key = "Wiki";
        let keys = ["Key", "Wiki", "Secret"];
        let plaintexts = ["Plaintext", "pedia", "Attack at dawn"];
        let expected_ciphertexts = [
            "BBF316E8D940AF0AD3",
            "1021BF0420",
            "45A01F645FC35B383552544B9BF5",
        ];

        let expected_ciphertexts = expected_ciphertexts
            .iter()
            .map(|s| s.to_lowercase())
            .collect::<Vec<String>>();

        for ((key, plaintext), expected_ciphertext) in
            keys.iter().zip(plaintexts).zip(expected_ciphertexts)
        {
            let mut rc4 = RC4::new(key.as_ref()).unwrap();
            let ciphertext = rc4.encrypt(plaintext.as_bytes());

            assert_eq!(expected_ciphertext, ciphertext.to_string())
        }
    }
}
