pub mod attacks;
pub mod rc4;

// Author: Filippo De Grandi
// Group: LactoseIntollerance
//
// How to run all tests:
//  cargo test -- --nocapture
//
// How to run a specific test:
// cargo test <test_name> -- --nocapture
//
// For the solution:
// cargo run solution -- --nocapture

#[cfg(test)]
mod tests {
    use crate::{attacks::RC4Attack, rc4::RC4};

    #[test]
    fn solution() {
        let key = "chiavesegretachenonserveinrealta";
        let mut attack = RC4Attack::new(key.as_ref());
        let ciphertext =
            "DDF62AE5641CFB52AB55DE95171FA86E900CEA7639B16AA5F0E58E1CBB".to_lowercase();
        let ciphertext = ciphertext.as_bytes().chunks(2).fold(
            Vec::with_capacity(ciphertext.len() / 2),
            |mut acc, chunk| {
                let byte = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
                acc.push(byte);
                acc
            },
        );

        // for testing purposes
        // let mut rc4 = RC4::new(key.as_ref()).unwrap();
        // let ciphertext = rc4.encrypt("We shall attack all intruders ".as_bytes());
        // let ciphertext = ciphertext.as_bytes().to_vec();

        println!("ciphertext: {ciphertext:02x?}");
        let original_plaintext = "We shall attack all intruders ";
        let modified_plaintext = "We shall kiss & hug intruders ";

        let forged_ciphertext = attack.malleability(
            ciphertext.as_ref(),
            original_plaintext,
            modified_plaintext,
        );

        println!("forged ciphertext: {forged_ciphertext}");

        // for testing purposes
        // let decrypted_forged = RC4::decrypt(key.as_ref(), forged_ciphertext.as_bytes()).to_utf8();
        // println!("forged ciphertext decrypts to: {decrypted_forged}");
    }

    #[test]
    fn malleability_attack() {
        let key = "cicciopasticcio";
        let mut rc4 = RC4::new(key.as_ref()).unwrap();
        let original_plaintext = "piccolo attacco";
        let original_ciphertext = rc4.encrypt(original_plaintext.as_bytes());

        let mut attack = RC4Attack::new(key.as_ref());
        let modified_plaintext = "grande attacco ";

        let forged_ciphertext = attack.malleability(
            original_ciphertext.as_bytes(),
            original_plaintext,
            modified_plaintext,
        );

        let decrypted_forged = RC4::decrypt(key.as_ref(), forged_ciphertext.as_bytes())
            .to_utf8();
        println!("forged ciphertext: {forged_ciphertext}");
        println!("forged ciphertext decrypts to: {decrypted_forged}");
    }

    #[test]
    fn rc4_impl() {
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

            let decrypted = RC4::decrypt(key.as_ref(), ciphertext.as_bytes()).to_utf8();
            println!("{key}, {plaintext} -> {ciphertext} -> {decrypted}");
            assert_eq!(plaintext, decrypted);
            assert_eq!(expected_ciphertext, ciphertext.to_string())
        }
    }
}
