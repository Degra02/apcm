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

use curve25519_dalek::edwards::CompressedEdwardsY;
use hex::FromHex;
use strum::IntoEnumIterator;

use crate::eddsa::{VerifyMode, VerifyingKey};

fn main() {
    let test_inputs = gen_test_inputs();

    println!("     | VER1 | VER2 | VER3 | VER4 | VER5 | VER6 |");
    for (i, (msg, pk_bytes, sig)) in test_inputs.iter().enumerate() {
        let compressed = CompressedEdwardsY(*pk_bytes);
        let point = compressed
            .decompress()
            .expect("public key decompression failed");
        let verifying_key = VerifyingKey { compressed, point };

        print!("INP{} |", i + 1);
        for mode in VerifyMode::iter() {
            let result = verifying_key.verify(msg, sig, mode);
            print!(" {:<4} |", if result.is_ok() { " ■" } else { " □" });
        }
        println!();
    }
}

fn gen_test_inputs() -> Vec<(Vec<u8>, [u8; 32], [u8; 64])> {
    let msg = "74657374206d65737361676520666f722065646765206361736520766572696669636174696f6e";
    let msg = Vec::from_hex(msg).expect("invalid hex message");
    // message|signature|pubkey
    const INP1: &str = "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000|edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    const INP2: &str = "5f5da7b0ec7d4e0271f5274526b55a9fb5c52e8c258a82e038bc89e0d77b7d76f4de58846e691a780aa20c3b6105a7c336ae89e8f96e35a31176d5bebb9d350f|0100000000000000000000000000000000000000000000000000000000000080";
    const INP3: &str = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000|ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const INP4: &str = "9051a15e6fbfdb6aeda3c3e3d1b6c48ee159053b495691e2cf1d2befd6a59c6f5dacb98ec9aa63a0078d32d44b762a9434eaec1fb069e7134e72636dc9bedc01|0100000000000000000000000000000000000000000000000000000000000000";
    const INP5: &str = "0100000000000000000000000000000000000000000000000000000000000080474c2d0c42b5f80a91613709579f284098d96a890387de114f1021bf55c0280c|79a389f31398afc69ba1ce2c08051e07f8d627ec229f079d9d056f7e44f9e291";
    const INP6: &str = "187c2c7fb655e24e0e67988d8195f31907fa23253c85459b301bdcca88bf46de96e7f5cfaa4f8bf71747d8d8c3794cf96fdd560cf696eb479859f7697900f50a|25b2d8754b5117e6366b8399d5228dc952f6304f3c518b175add51f378518c45";

    let constants = [INP1, INP2, INP3, INP4, INP5, INP6];
    let mut inputs: Vec<(Vec<u8>, [u8; 32], [u8; 64])> = Vec::new();

    for c in constants.iter() {
        let parts: Vec<&str> = c.split('|').collect();
        let sig_vec = Vec::from_hex(parts[0]).expect("invalid hex signature");
        let pub_vec = Vec::from_hex(parts[1]).expect("invalid hex pubkey");

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_vec[..64]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pub_vec[..32]);

        inputs.push((msg.clone(), pk, sig));
    }

    inputs
}

#[cfg(test)]
mod tests {
    use crate::eddsa::{SigningKey, VerifyMode};
    use hex_literal::hex;
    use itertools::izip;

    #[test]
    fn verify() {
        let secret_key: [u8; 32] =
            hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let signing_key = SigningKey::generate(&secret_key);

        let message = hex!("af82");
        let signature = signing_key.sign(&message);

        assert!(
            signing_key
                .verify(&message, &signature, VerifyMode::Ver1Strict)
                .is_ok()
        )
    }

    #[test]
    fn sign_kats() {
        let secret_keys: Vec<[u8; 32]> = vec![
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
            hex!("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
        ];

        let messages: Vec<&[u8]> = vec![
            b"",
            hex!("72").as_ref(),
            hex!("af82").as_ref(),
            hex!("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0").as_ref()
        ];

        let expected_public_keys: Vec<[u8; 32]> = vec![
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            hex!("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
        ];

        let expected_signatures: Vec<[u8; 64]> = vec![
            hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
            hex!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
            hex!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
            hex!(
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
            ),
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
        let secret_key: [u8; 32] =
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let signing_key = SigningKey::generate(&secret_key);

        let public_key = &signing_key.verifying_key;
        println!(
            "Public Key: {}",
            hex::encode(public_key.compressed.as_bytes())
        );

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
