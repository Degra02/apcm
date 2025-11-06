use crate::{attack::Attacker, utils::CustomError};
use hex_literal::hex;
mod attack;
mod utils;

// Author: Filippo De Grandi
// Group: es geht um die Wurst
// How to run:
// ```
// cargo run --release
// (will take long)
// ```
//
// The decimal number obtained from running the attack on the server is:
// 8126909346732895552832680717220929616097849623675250195093952090503665860206128499907087726347990639484388867644184638996449734722096108887967941758581184429828980071961784161017064967105676617129392976269419021845320646612091868496432853736785840242880433388131131739944486265371184261272339189514466163
//
// Which is the decimal representation of the following unpadded message:
// `I bear the sigil of Raloberon, thus I shall pass`
//
// The `unpad_result` test can be used to verify the unpadding of the final result
// via `cargo test`
//
// NOTE:
// The attack took around 3 hours to complete / 350k requests to the server (I don't actually know
// the number because that version did not have statistics).
// Strangely, the local connection (through Docker) was slower that the remote one.
//
// I used an error based oracle, altough I believe also the timing oracle would have worked fine.
// The long waiting times for any type of result made it impractical to test extensively
//
//
// NOTE++:
// This version is a parallelized version of the attack.
// The correct result has been obtained with the single threaded version, while the parallelized
// version has not (yet) been able to complete the attack, either to subtle bugs or server rate limiting.
// The performance improvements of the parallelization are not a straight division of the time by the number of threads,
// since there is some overhead in managing threads and sending requests to the oracle.
//
// > After a long test, the parallelized version crashed with a OOM error, probably due to the high
// number of BigUint instances created and stored in memory.

const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");


#[allow(dead_code)]
const TEST_URL: &str = "http://127.0.0.1:8000";
#[allow(dead_code)]
const TEST_CIPHERTEXT: [u8; 128] = hex!("6a351c8a4e160a584dc287c50f77b1589f63b45411ffdce9f25d72e99bdbaaa10970fb8a7502f63ca0c24db53cd34b3720c7c54f0d33446c9db92bb947bcf785942c4746c06e39dbb38c0536e419dff6ff1a8b032fdeb4319f68db72e3d7c52f1d2130865afb54cd76497ce9e6df0b2f4469c5f948af5740b08d87dd06922ea2");

fn main() -> Result<(), CustomError> {
    let mut attacker = Attacker::new(TEST_URL, &TEST_CIPHERTEXT)?;
    // let mut attacker = Attacker::new(URL, &CIPHERTEXT)?;
    let res = attacker.attack()?;

    println!("message decimal: {}", res);

    let b = res.to_bytes_be();
    let separator = b.iter().position(|&x| x == 0x00).unwrap();
    let unpadded = &b[(separator + 1)..];

    println!("decrypted plaintext: {}", String::from_utf8_lossy(unpadded));

    Ok(())
}

#[test]
fn parallel_attack() -> Result<(), CustomError> {
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
fn serial_attack() -> Result<(), CustomError> {
    let mut attacker = Attacker::new(TEST_URL, &TEST_CIPHERTEXT)?;
    let res = attacker.attack_serial()?;

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
