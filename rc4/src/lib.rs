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

        let decrypted_forged = RC4::decrypt(key.as_ref(), &forged_ciphertext).to_utf8().unwrap();
        println!("forged ciphertext decrypts to: {decrypted_forged}");
    }

    #[test]
    fn rc4_impl() {
        let key = "chiavegrossa";
        let mut rc4 = RC4::new(key.as_ref()).unwrap();

        let plaintext = "We shall attack all intruders ";

        let ciphertext = rc4.encrypt(plaintext.as_bytes());

        println!("ciphertext: {ciphertext}");

        let decrypted = RC4::decrypt(key.as_bytes(), ciphertext.as_bytes())
            .to_utf8()
            .unwrap();
        println!("decrypted plaintext: {decrypted}");
    }
}

// We shall attack all intruders
// We shall kissss all intruders
