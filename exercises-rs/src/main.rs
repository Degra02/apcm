//! # Last Slice Of Light
//! Author: Filippo De Grandi
//! Group: questavoltamelosonoricordato
//!
//! How to run:
//! ```
//! cargo run
//! ```
//!
//! The KAT test can be run with:
//! ```
//! cargo test -- --nocapture
//! ```
//!


pub mod sha3;

use sha3::{SHA3, ShaVariant};

fn main() {
    let to_encode: &str = "FLAG{the_curse_of_the_hex_is_broken_the_door_of_the_crypt_is_now_open}";
    let mut hasher = SHA3::new(ShaVariant::SHA3_224);
    hasher.update(to_encode.as_bytes());

    let digest = hasher.finalize();

    println!("\nSHA3-256: {digest}");
}
