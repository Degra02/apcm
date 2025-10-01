// # Last Slice Of Light
// Author: Filippo De Grandi
// Group: :(){ :|: & };:
//
// How to run the solution:
// ```
// cargo test solution -- --nocapture
// ```
//
// The KAT test can be run with:
// ```
// cargo test kat_all -- --nocapture
// ```
//

pub mod sha3;

#[cfg(test)]
mod tests {
    use crate::sha3::{ShaVariant, SHA3};

    #[test]
    fn solution() {
        let to_encode: &str =
            "FLAG{the_curse_of_the_hex_is_broken_the_door_of_the_crypt_is_now_open}";
        let mut hasher = SHA3::new(ShaVariant::SHA3_224);
        hasher.update(to_encode.as_bytes());

        let digest = hasher.finalize();

        println!("\nSHA3-256: {digest}");
    }

    #[test]
    fn kat_all() {
        let strings_to_encode = [
            "",
            "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            &"a".repeat(1_000_000),
        ];

        let variants = [
            ShaVariant::SHA3_224,
            ShaVariant::SHA3_256,
            ShaVariant::SHA3_384,
            ShaVariant::SHA3_512,
        ];

        let expected_hashes = [
            // SHA3-224
            [
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
                "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
                "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
                "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
            ],
            // SHA3-256
            [
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
                "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
                "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
            ],
            // SHA3-384
            [
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
                "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
                "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
                "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"
            ],
            // SHA3-512
            [
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
                "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185",
                "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
            ]
        ];

        for (i, &to_encode) in strings_to_encode.iter().enumerate() {
            for (j, variant) in variants.iter().enumerate() {
                let mut hasher = SHA3::new(*variant);
                hasher.update(to_encode.as_bytes());
                let digest = hasher.finalize();
                println!("\nVariant: {variant:?}, Input: \"{to_encode:.50}\"");
                assert_eq!(digest.to_string(), expected_hashes[j][i]);
                hasher.reset();
            }
        }
    }
}
