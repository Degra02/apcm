#![allow(dead_code)]
#![allow(renamed_and_removed_lints)]

use std::fmt::{Display, LowerHex};


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest(Vec<u8>);

impl Digest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl LowerHex for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ShaVariant {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl ShaVariant {
    /// Returns rate r, capacity c and output length for the given SHA-3 variant.
    pub fn parameters(&self) -> (usize, usize, usize) {
        match self {
            ShaVariant::SHA3_224 => (1152, 448, 224),
            ShaVariant::SHA3_256 => (1088, 512, 256),
            ShaVariant::SHA3_384 => (832, 768, 384),
            ShaVariant::SHA3_512 => (576, 1024, 512),
        }
    }
}

pub struct SHA3(Keccak);

impl SHA3 {
    pub fn new(variant: ShaVariant) -> Self {
        let (rate, capacity, output_length) = variant.parameters();
        SHA3(Keccak::new(rate/8, capacity/8, output_length/8))
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.absorb(input);
    }

    pub fn finalize(&mut self) -> Digest {
        Digest(self.0.squeeze())
    }

    pub fn reset(&mut self) {
        self.0.reset();
    }
}

const RHO: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const PI: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];


#[derive(Debug)]
struct Keccak {
    state: [u64; 25],
    rate: usize,
    capacity: usize,
    output_length: usize,
    buffer: Vec<u8>,
}

impl Keccak {
    pub fn new(rate: usize, capacity: usize, output_length: usize) -> Self {
        Keccak {
            state: [0u64; 25],
            rate,
            capacity,
            output_length,
            buffer: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = [0u64; 25];
        self.buffer.clear();
    }

    fn print_last_slice(&self) {
        println!("Last slice: ");
        for y in 0..5 {
            for x in 0..5 {
                let lane = self.state[x + 5 * y];
                let bit = ((lane >> 63) & 0x1) as u8;
                print!("{bit}");
            }
            println!();
        }
    }

    /// Absorb function, can assume full bytes input
    pub fn absorb(&mut self, input: &[u8]) {
        self.buffer.extend_from_slice(input);
        let block_size = self.rate;

        while self.buffer.len() >= block_size {
            let block = self.buffer.drain(..self.rate).collect::<Vec<u8>>();
            self.absorb_block(&block);
        }
    }

    pub fn squeeze(&mut self) -> Vec<u8> {
        self.buffer.push(0x06);
        while self.buffer.len() < self.rate {
            self.buffer.push(0x00);
        }

        if let Some(last) = self.buffer.last_mut() {
            *last ^= 0x80;
        }

        // absorbing the final block
        let final_block: Vec<u8> = self.buffer.drain(..).collect();
        self.absorb_block(&final_block);


        let mut output = Vec::new();
        while output.len() < self.output_length {
            let num_lanes = self.rate / 8;
            for i in 0..num_lanes {
                let lane_bytes = self.state[i].to_le_bytes();
                for &byte in &lane_bytes {
                    output.push(byte);
                    if output.len() >= self.output_length {
                        return output;
                    }
                }
            }

            // if more output is needed
            self.keccak_f();
        }

        output
    }

    fn absorb_block(&mut self, block: &[u8]) {
        self.xor_block(block);
        self.keccak_f();
    }

    fn xor_block(&mut self, block: &[u8]) {
        let mut chunks = block.chunks_exact(8);
        for (s, chunk) in self.state.iter_mut().zip(&mut chunks) {
            *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut last_chunk = [0u8; 8];
            last_chunk[..remainder.len()].copy_from_slice(remainder);
            let n = block.len() / 8;
            self.state[n] ^= u64::from_le_bytes(last_chunk);
        }
    }


    /// Keccak-f[1600] permutation
    fn keccak_f(&mut self) {
        for round in 0..24 {
            self.theta();
            self.rho_pi();

            if round == 23 {
                self.print_last_slice();
            }

            self.chi();
            self.iota(round);
        }
    }

    fn theta(&mut self) {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = self.state[x] ^ self.state[x + 5] ^ self.state[x + 10] ^ self.state[x + 15] ^ self.state[x + 20];
        }


        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                self.state[x + 5 * y] ^= d[x];
            }
        }
    }

    fn rho_pi(&mut self) {
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = self.state[x + 5 * y].rotate_left(PI[x][y]);
            }
        }
        self.state = b;
    }

    fn chi(&mut self) {
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[x + 5 * y] = self.state[x + 5 * y] ^ ((!self.state[((x + 1) % 5) + 5 * y]) & self.state[((x + 2) % 5) + 5 * y]);
            }
        }
        self.state = b;
    }

    fn iota(&mut self, round: usize) {
        self.state[0] ^= RHO[round];
    }
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
            let mut hasher = SHA3::new(variant.clone());
            hasher.update(to_encode.as_bytes());
            let digest = hasher.finalize();
            println!("\nVariant: {variant:?}, Input: \"{to_encode}\"");
            assert_eq!(digest.to_string(), expected_hashes[j][i]);
            hasher.reset();
        }
    }
}
