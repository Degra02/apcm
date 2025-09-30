#![allow(dead_code)]
#![allow(non_upper_case_globals)]

//! # Last Slice Of Light
//! Author: Filippo De Grandi
//! Group: questavoltamelosonoricordato

use std::fmt::{Display, LowerHex};

enum ShaVariant {
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

struct SHA3(Keccak);

impl SHA3 {
    pub fn new(variant: ShaVariant) -> Self {
        let (rate, capacity, output_length) = variant.parameters();
        SHA3(Keccak::new(rate/8, capacity/8, output_length/8))
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.absorb(input);
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        self.0.squeeze()
    }

    pub fn reset(&mut self) {
        self.0.reset();
    }
}

struct Digest(Vec<u8>);

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

const round_constants: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const rotation_offsets: [[u32; 5]; 5] = [
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

        // let last_idx = self.buffer.len() - 1;
        // self.buffer[last_idx] ^= 0x80;
        if let Some(last) = self.buffer.last_mut() {
            *last ^= 0x80;
        }

        // absorbing the final block
        let final_block: Vec<u8> = self.buffer.drain(..).collect();
        self.absorb_block(&final_block);

        // let mut output = Vec::new();
        // while output.len() < self.output_length {
        //     let num_lanes = self.rate / 8;
        //     for i in 0..num_lanes {
        //         let lane_bytes = self.state[i].to_le_bytes();
        //         for &byte in &lane_bytes {
        //             output.push(byte);
        //             if output.len() >= self.output_length { return output; }
        //         }
        //     }
        //
        //     // if more output is needed
        //     self.keccak_f();
        // }


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
                b[y + 5 * ((2 * x + 3 * y) % 5)] = self.state[x + 5 * y].rotate_left(rotation_offsets[x][y]);
            }
        }
        self.state = b;

        // let mut b = [0u64; 25];
        // for x in 0..5 {
        //     for y in 0..5 {
        //         let x_prime = (2 * x + 3 * y) % 5;
        //         // target index is x' + 5*y
        //         b[x_prime + 5 * y] = self.state[x + 5 * y].rotate_left(rotation_offsets[x][y]);
        //     }
        // }
        // self.state = b;
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
        self.state[0] ^= round_constants[round];
    }
}




#[test]
fn last_slice_of_light() {
    let to_encode: &str = "FLAG{the_curse_of_the_hx_is_broken_the_door_of_the_crypt_is_now_open}";
    let mut hasher = SHA3::new(ShaVariant::SHA3_224);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

}


#[test]
fn kat_sha3_224() {
    let to_encode: &str = "";
    let mut hasher = SHA3::new(ShaVariant::SHA3_224);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    let hex_digest = digest.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // empty string
    assert_eq!(
        hex_digest,
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    );

    // "abc" string
    let to_encode: &str = "abc";
    hasher.reset();
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    let hex_digest = digest.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        hex_digest,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
}

#[test]
fn kat_sha3_256() {
    let to_encode: &str = "";
    let mut hasher = SHA3::new(ShaVariant::SHA3_256);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();

    let hex_digest = digest.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert_eq!(
        hex_digest,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn kat_sha3_384() {
    let to_encode: &str = "";
    let mut hasher = SHA3::new(ShaVariant::SHA3_384);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();
    let hex_digest = digest.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert_eq!(
        hex_digest,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
}

#[test]
fn kat_sha3_512() {
    let to_encode: &str = "";
    let mut hasher = SHA3::new(ShaVariant::SHA3_512);
    hasher.update(to_encode.as_bytes());
    let digest = hasher.finalize();
    let hex_digest = digest.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert_eq!(
        hex_digest,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
}
