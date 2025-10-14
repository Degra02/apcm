use std::fmt::{Display, LowerHex};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum InvalidLength {
    Key,
    Constant,
    Counter,
    Nonce,
}

const ROUNDS: usize = 20;
const DEFAULT_CONSTANT: [u8; 16] = *b"expand 32-byte k";

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Prng {
    constant: [u32; 4],

    #[zeroize]
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],
}

impl Prng {
    pub fn new(
        key: &[u8],
        nonce: [u32; 3],
        counter: Option<u32>,
        constant: Option<&[u8; 16]>,
    ) -> Result<Self, InvalidLength> {
        if key.len() != 32 {
            return Err(InvalidLength::Key);
        }

        if nonce.len() != 3 {
            return Err(InvalidLength::Nonce);
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        let key_array = key_array
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let constant_bytes = constant.unwrap_or(&DEFAULT_CONSTANT);
        let constant_vec = constant_bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        // Counter
        let counter = counter.unwrap_or_default();

        Ok(Prng {
            constant: constant_vec.try_into().unwrap(),
            key: key_array,
            counter,
            nonce,
        })
    }

    fn state(&self) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&self.constant);
        state[4..12].copy_from_slice(&self.key);
        state[12] = self.counter;
        state[13..16].copy_from_slice(&self.nonce);

        state
    }

    fn chacha_block(&self) -> [u32; 16] {
        let state: [u32; 16] = self.state();
        let mut x: [u32; 16] = self.state();

        for _ in (0..ROUNDS).step_by(2) {
            // Odd round
            Prng::quarter_round(&mut x, 0, 4, 8, 12);
            Prng::quarter_round(&mut x, 1, 5, 9, 13);
            Prng::quarter_round(&mut x, 2, 6, 10, 14);
            Prng::quarter_round(&mut x, 3, 7, 11, 15);

            // Even round
            Prng::quarter_round(&mut x, 0, 5, 10, 15);
            Prng::quarter_round(&mut x, 1, 6, 11, 12);
            Prng::quarter_round(&mut x, 2, 7, 8, 13);
            Prng::quarter_round(&mut x, 3, 4, 9, 14);
        }

        x.iter_mut().enumerate().for_each(|(i, v)| {
            *v = v.wrapping_add(state[i]);
        });

        x
    }

    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] ^= x[a];
        x[d] = x[d].rotate_left(16);

        x[c] = x[c].wrapping_add(x[d]);
        x[b] ^= x[c];
        x[b] = x[b].rotate_left(12);

        x[a] = x[a].wrapping_add(x[b]);
        x[d] ^= x[a];
        x[d] = x[d].rotate_left(8);

        x[c] = x[c].wrapping_add(x[d]);
        x[b] ^= x[c];
        x[b] = x[b].rotate_left(7);
    }
}

impl Iterator for &mut Prng {
    type Item = [u8; 64];

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.chacha_block();

        self.counter = self.counter.wrapping_add(1);

        let mut bytes = [0u8; 64];
        for (i, chunk) in bytes.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&block[i].to_le_bytes());
        }

        Some(bytes)
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20(#[zeroize] Prng);

#[allow(dead_code)]
impl ChaCha20 {
    pub fn new(
        key: &[u8],
        nonce: &[u8; 12],
        counter: Option<&[u8; 4]>,
        constant: Option<&[u8; 16]>,
    ) -> Result<Self, InvalidLength> {
        if nonce.len() != 12 {
            return Err(InvalidLength::Nonce);
        }

        let nonce_array: [u32; 3] = nonce
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let counter_array: u32;
        if let Some(c) = counter {
            if c.len() != 4 {
                return Err(InvalidLength::Counter);
            }
            counter_array = u32::from_le_bytes(*c);
        } else {
            counter_array = 0u32;
        }

        let state = Prng::new(key, nonce_array, Some(counter_array), constant)?;
        Ok(ChaCha20(state))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Output {
        let ciphertext: Vec<u8> = plaintext
            .chunks(64)
            .zip(&mut self.0)
            .flat_map(|(chunk, k)| chunk.iter().enumerate().map(move |(i, &b)| b ^ k[i]))
            .collect();

        Output(ciphertext)
    }

    pub fn keystream(&mut self, size: usize) -> Vec<u8> {
        self.0.into_iter()
            .flatten()
            .take(size)
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output(pub Vec<u8>);

#[allow(dead_code)]
impl Output {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_utf8(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.0.clone()) }
    }
}

impl Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl LowerHex for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
