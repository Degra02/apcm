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
    use itertools::izip;

    #[test]
    fn sign_kats() {
        let secret_keys: Vec<[u8; 32]> = vec![
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
        ];

        let messages: Vec<&[u8]> = vec![
            b"",
            hex!("72").as_ref(),
            hex!("af82").as_ref(),
        ];

        let expected_public_keys: Vec<[u8; 32]> = vec![
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        ];

        let expected_signatures: Vec<[u8; 64]> = vec![
            hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            hex!("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            hex!("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ];

        for (sk, msg, exp_pk, exp_sig) in izip!(
            secret_keys,
            messages,
            expected_public_keys,
            expected_signatures,
        ) {
            let signing_key = SigningKey::generate(&sk);
            let public_key = &signing_key.verifying_key;
            assert_eq!(public_key.compressed.as_bytes(), &exp_pk);

            let signature = signing_key.sign(msg);
            assert_eq!(&signature, &exp_sig);
        }
    }

    #[test]
    fn sign_message() {
        let secret_key: [u8; 32] = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let signing_key = SigningKey::generate(&secret_key);

        let public_key = &signing_key.verifying_key;
        println!("Public Key: {}", hex::encode(public_key.compressed.as_bytes()));

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
