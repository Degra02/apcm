#![allow(dead_code)]
#![allow(non_upper_case_globals)]

//! # Last Slice Of Light
//! Author: Filippo De Grandi
//! Group: questavoltamelosonoricordato


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

    /// Absorb function, can assume full bytes input
    pub fn absorb(&mut self, input: &[u8]) {
        self.buffer.extend_from_slice(input);

        
    }

    pub fn squeeze(&mut self) -> Vec<u8> {
        todo!()
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
}
