use std::str::FromStr;

use crate::{attack::{unpad_pkcs1_v15, Attacker}, utils::CustomError};
use hex_literal::hex;
use num_bigint::BigUint;

mod attack;
mod utils;
mod bytes;

// Author: Filippo De Grandi
// Group: es geht um die Wurst
// How to run:
// ```
// cargo run --release (will take long)
// ```
//
// The result from running the attack on the server is:
// message: 8126909346732895552832680717220929616097849623675250195093952090503665860206128499907087726347990639484388867644184638996449734722096108887967941758581184429828980071961784161017064967105676617129392976269419021845320646612091868496432853736785840242880433388131131739944486265371184261272339189514466163
//
//  Which is the decimal representation of the plaintext.
//
//

const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const TEST_URL: &str = "http://localhost:8000";

const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");

fn main() -> Result<(), CustomError> {
    // let mut attacker = Attacker::new(TEST_URL, None)?;
    let mut attacker = Attacker::new(URL, Some(&CIPHERTEXT))?;
    let res = attacker.attack()?;

    println!(
        "message decimal: {}",
        res
    );

    let a = "8126909346732895552832680717220929616097849623675250195093952090503665860206128499907087726347990639484388867644184638996449734722096108887967941758581184429828980071961784161017064967105676617129392976269419021845320646612091868496432853736785840242880433388131131739944486265371184261272339189514466163";

    let res = BigUint::from_str(a).unwrap();

    let k = 128;
    let b = res.to_bytes_be();

    let separator = b.iter().position(|&x| x == 0x00).unwrap();
    let unpadded = &b[(separator + 1)..];

    println!("message unpadded: {}", String::from_utf8_lossy(unpadded));

    Ok(())
}
