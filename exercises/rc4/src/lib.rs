pub mod attacks;
pub mod rc4;

// Author: Filippo De Grandi
// Group: turbofish ::<>
//
// How to run all tests:
//  cargo test -- --nocapture
//
// How to run a specific test:
// cargo test <test_name> -- --nocapture
//
// For the solution:
// cargo test solution -- --nocapture
// This will print the forged ciphertext in hex format

#[cfg(test)]
mod tests {
    use crate::{attacks::RC4Attack, rc4::RC4};

    #[test]
    fn solution() {
        let key = "chiavesegretachenonserveinrealta";
        let rc4 = RC4::new(key.as_ref()).unwrap();
        let mut attack = RC4Attack::new(rc4.clone(), key.as_ref());
        let ciphertext =
            "DDF62AE5641CFB52AB55DE95171FA86E900CEA7639B16AA5F0E58E1CBB".to_lowercase();
        let ciphertext = hex::decode(ciphertext).expect("Decoding failed");

        // for testing purposes
        // let mut rc4 = RC4::new(key.as_ref()).unwrap();
        // let ciphertext = rc4.encrypt("We shall attack all intruders ".as_bytes());
        // let ciphertext = ciphertext.as_bytes().to_vec();

        let original_plaintext = "We shall attack all intruders ";
        let modified_plaintext = "We shall kiss & hug intruders ";

        let forged_ciphertext =
            attack.malleability(ciphertext.as_ref(), original_plaintext, modified_plaintext);

        println!("forged ciphertext: {forged_ciphertext}");

        // for testing purposes
        // let decrypted_forged = RC4::decrypt(key.as_ref(), forged_ciphertext.as_bytes()).to_utf8();
        // println!("forged ciphertext decrypts to: {decrypted_forged}");
    }

    #[test]
    fn recover_key_stream() {
        let key = "Key";
        let mut rc4 = RC4::new(key.as_ref()).unwrap();

        let plaintext = "Plaintext";
        let ciphertext = rc4.encrypt(plaintext.as_bytes());

        let mut attack = RC4Attack::new(rc4.clone(), key.as_ref());
        let recovered_keystream = attack.recover_key_stream(plaintext, ciphertext.as_bytes());

        assert_eq!(
            hex::decode("EB9F7781B734CA72A7").expect("Decoding failed"),
            recovered_keystream
        );
    }

    #[test]
    fn malleability_attack() {
        let key = "cicciopasticcio";
        let mut rc4 = RC4::new(key.as_ref()).unwrap();

        let original_plaintext = "piccolo attacco";
        let original_ciphertext = rc4.encrypt(original_plaintext.as_bytes());

        let mut attack = RC4Attack::new(rc4.clone(), key.as_ref());
        let modified_plaintext = "grande attacco ";

        let forged_ciphertext = attack.malleability(
            original_ciphertext.as_bytes(),
            original_plaintext,
            modified_plaintext,
        );

        let decrypted_forged = RC4::decrypt(key.as_ref(), forged_ciphertext.as_bytes());
        println!("forged ciphertext: {forged_ciphertext}");
        println!(
            "forged ciphertext decrypts to: {}",
            decrypted_forged.to_utf8()
        );

        assert_eq!(modified_plaintext.as_bytes(), decrypted_forged.as_bytes());
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

        for ((key, plaintext), expected_ciphertext) in
            keys.iter().zip(plaintexts).zip(expected_ciphertexts)
        {
            let mut rc4 = RC4::new(key.as_ref()).unwrap();
            let ciphertext = rc4.encrypt(plaintext.as_bytes());

            let decrypted = RC4::decrypt(key.as_ref(), ciphertext.as_bytes()).to_utf8();
            println!("{key}, {plaintext} -> {ciphertext} -> {decrypted}");

            assert_eq!(plaintext, decrypted);
            assert_eq!(
                hex::decode(expected_ciphertext).expect("Decoding failed"),
                ciphertext.as_bytes()
            )
        }
    }
}
