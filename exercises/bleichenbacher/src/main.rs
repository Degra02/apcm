use crate::{attack::Attacker, utils::CustomError};
use hex_literal::hex;
mod attack;
mod utils;

// Author: Filippo De Grandi
// Group: es geht um die Wurst
// How to run:
// ```
// cargo run --release
// ```
//
// The decimal number obtained from running the attack on the server is:
// 8126909346732895552832680717220929616097849623675250195093952090503665860206128499907087726347990639484388867644184638996449734722096108887967941758581184429828980071961784161017064967105676617129392976269419021845320646612091868496432853736785840242880433388131131739944486265371184261272339189514466163
//
// Which is the decimal representation of the following unpadded message:
// `I bear the sigil of Raloberon, thus I shall pass`
//
// The `unpad_result` test can be used to verify the unpadding of the final result
// via `cargo test unpad_result`
//
// NOTE:
// The attack with the sequential version took around 3 hours to complete.
//
// This version is a parallelized implementation of the attack.
// It works MUCH faster (16 threads on my machine) than the sequential one.
//
// It took 9m40s to complete the attack against the local docker.
//
// Remotely, latency and / or server saturation causes a significant slowdown.
// It took 46m58s to complete the attack against the remote server.
//

const URL: &str = "https://juicy-allyn-mystic-rogue-04c667cf.koyeb.app";
const CIPHERTEXT: [u8; 128] = hex!(
    "2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817"
);

fn main() -> Result<(), CustomError> {
    let mut attacker = Attacker::new(URL, &CIPHERTEXT)?;
    let res = attacker.attack()?;

    println!("message decimal: {}", res);

    let b = res.to_bytes_be();
    let separator = b.iter().position(|&x| x == 0x00).unwrap();
    let unpadded = &b[(separator + 1)..];

    println!("decrypted plaintext: {}", String::from_utf8_lossy(unpadded));

    Ok(())
}

#[test]
fn test_attack() -> Result<(), CustomError> {
    const TEST_URL: &str = "http://127.0.0.1:8000";
    const TEST_CIPHERTEXT: [u8; 128] = hex!("78d83ac28d121336b52ce282ac0ae89656ebfa3380f29f18a442ad97bf5430dac1b4b3db347aa434b3d56857ebdd59ad1040a042b2d3142646ed99908a60ab5d3602e04dab1d7f0a10c8e4c9bd45c12630d842aad01721371b6d63fbb91b3b937dca0f10de8fdb0c158f7dbe1cddbadd5fb70c03b0f1bc0631cbf5aa74e162c6"); // placeholder

    let mut attacker = Attacker::new(TEST_URL, &TEST_CIPHERTEXT)?;
    let res = attacker.attack()?;

    println!("message decimal: {}", res);

    let b = res.to_bytes_be();
    let separator = b.iter().position(|&x| x == 0x00).unwrap();
    let unpadded = &b[(separator + 1)..];

    println!("decrypted plaintext: {}", String::from_utf8_lossy(unpadded));
    Ok(())
}

#[test]
fn unpad_result() {
    let decimal = "8126909346732895552832680717220929616097849623675250195093952090503665860206128499907087726347990639484388867644184638996449734722096108887967941758581184429828980071961784161017064967105676617129392976269419021845320646612091868496432853736785840242880433388131131739944486265371184261272339189514466163";

    let res = <num_bigint::BigUint as std::str::FromStr>::from_str(decimal).unwrap();

    let b = res.to_bytes_be();
    let separator = b.iter().position(|&x| x == 0x00).unwrap();
    let unpadded = &b[(separator + 1)..];

    assert_eq!(
        unpadded,
        b"I bear the sigil of Raloberon, thus I shall pass"
    );
}
