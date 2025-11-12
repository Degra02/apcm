#![allow(dead_code)]

mod eddsa;
mod utils;

// Name: Filippo De Grandi
// Group: curvy
//
// Why the crate curve25519-dalek is used in this implementation:
// - seamless integraiton with sha2 crate
// - high level abstractions for point and scalar operations
// - well maintained and widely used in the Rust cryptographic community

fn main() {
    let secret_key = rand::random_iter::<u8>().take(32).collect::<Vec<u8>>();
}

#[cfg(test)]
mod tests {
}
