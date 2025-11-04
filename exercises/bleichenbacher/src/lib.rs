#![allow(dead_code)]
mod attack;
mod utils;

use hex_literal::hex;

// Author: Filippo De Grandi
// Group: es geht um die Wurst
// How to run:
// ```
// cargo test solution -- --nocapture
// ```


const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const TEST_URL: &str = "http://localhost:8000";

const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");

#[cfg(test)]
mod tests {
    use crate::{attack::Attacker, utils::CustomError, CIPHERTEXT, TEST_URL, URL};

    #[test]
    fn solution() -> Result<(), CustomError> {
        let mut attacker = Attacker::new(URL, Some(&CIPHERTEXT))?;
        let res = attacker.bleichenbacher_attack()?;

        println!(
            "Decrypted plaintext: {}",
            String::from_utf8_lossy(&res)
        );

        Ok(())
    }

    #[test]
    fn test_attack() -> Result<(), CustomError> {
        let mut attacker = Attacker::new(TEST_URL, None)?;
        let res = attacker.bleichenbacher_attack()?;

        println!(
            "Decrypted plaintext: {}",
            String::from_utf8_lossy(&res)
        );



        Ok(())
    }

    #[test]
    fn deserialize() -> Result<(), CustomError> {
        let attacker = Attacker::new(TEST_URL, None)?;
        println!("State: {:?}", attacker.state);

        let res = attacker.encrypt("ciccio".as_bytes(), None)?;

        println!("{:?}", res);

        Ok(())
    }
}
