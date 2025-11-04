use crate::{attack::{unpad_pkcs1_v15, Attacker}, utils::CustomError};
use hex_literal::hex;

mod attack;
mod utils;

const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const TEST_URL: &str = "http://localhost:8000";

const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");

fn main() -> Result<(), CustomError> {
    // let mut attacker = Attacker::new(URL, Some(&CIPHERTEXT))?;
    let mut attacker = Attacker::new(TEST_URL, None)?;
    let res = attacker.bleichenbacher_attack()?;
    println!("{:?}", res);

    match unpad_pkcs1_v15(&res) {
        Ok(plaintext) => {
            println!("Recovered plaintext ({} bytes): {:?}", plaintext.len(), plaintext);
            // If the original message was printable UTF-8:
            if let Ok(s) = std::str::from_utf8(&plaintext) {
                println!("As UTF-8: {}", s);
            } else {
                println!("Plaintext is not valid UTF-8; raw bytes shown above.");
            }
        }
        Err(e) => {
            eprintln!("Unpadding failed: {:?}", e);
        }
    }

    Ok(())
}
