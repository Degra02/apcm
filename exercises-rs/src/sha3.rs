#![allow(dead_code)]
#![allow(renamed_and_removed_lints)]
#![allow(needless_range_loop)]

//! # Last Slice Of Light
//! Author: Filippo De Grandi
//! Group: questavoltamelosonoricordato

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
        println!("Last slice (z = 63) — 1 = safe tile:");
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
fn kat_sha3_224() {
    let to_encode: &str = "";
    let mut hasher = SHA3::new(ShaVariant::SHA3_224);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();


    // empty string
    assert_eq!(
        digest.to_string(),
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    );
    hasher.reset();

    // "abc" string
    let to_encode: &str = "abc";
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    assert_eq!(
        digest.to_string(),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
}

#[test]
fn kat_sha3_256() {
    let to_encode: &str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut hasher = SHA3::new(ShaVariant::SHA3_256);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    assert_eq!(
        digest.to_string(),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    );
}

#[test]
fn kat_sha3_384() {
    let to_encode: &str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let mut hasher = SHA3::new(ShaVariant::SHA3_384);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    assert_eq!(
        digest.to_string(),
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"
    );
}

#[test]
fn kat_sha3_512() {
    let to_encode: &str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let mut hasher = SHA3::new(ShaVariant::SHA3_512);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    assert_eq!(
        digest.to_string(),
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
    );
}
