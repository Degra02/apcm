pub mod sha3;

use sha3::{SHA3, ShaVariant};

fn main() {
    let to_encode: &str = "FLAG{the_curse_of_the_hex_is_broken_the_door_of_the_crypt_is_now_open}";
    let mut hasher = SHA3::new(ShaVariant::SHA3_224);
    hasher.update(to_encode.as_bytes());

    let digest = hasher.finalize();
    let state = hasher.get_state();

    println!("SHA3-256: {digest}");
    println!("State: {state:?}");
}
