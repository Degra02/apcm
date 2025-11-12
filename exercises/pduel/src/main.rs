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
    use crate::eddsa::SigningKey;
    use hex_literal::hex;

    #[test]
    fn sign_message() {
        let secret_key: [u8; 32] = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let signing_key = SigningKey::generate(&secret_key);

        let message = b"";
        let signature = signing_key.sign(message);

        println!("Signature: {}", hex::encode(signature));
    }

    #[test]
    fn key_generation() {
        let secret_key = rand::random_iter::<u8>().take(32).collect::<Vec<u8>>();
        let signing_key = SigningKey::generate(&secret_key.try_into().unwrap());

        println!("{:?}", signing_key);
    }
}
