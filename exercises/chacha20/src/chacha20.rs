#![allow(dead_code)]

use std::fmt::{Display, LowerHex};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum InvalidLength {
    Key,
    Constant,
    Counter,
    Nonce,
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

const ROUNDS: usize = 20;

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20State {
    constant: [u32; 4],

    #[zeroize]
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],
}

impl ChaCha20State {
    pub fn new(
        key: &[u8],
        nonce: [u32; 3],
        constant: Option<&[u8]>,
    ) -> Result<Self, InvalidLength> {
        // Key
        if key.len() != 32 {
            return Err(InvalidLength::Key);
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        let key_array = key_array
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        // Constant
        let mut constant_val = [0u8; 16];
        if let Some(c) = constant {
            if c.len() != 16 {
                return Err(InvalidLength::Constant);
            }
            constant_val.copy_from_slice(c);
        } else {
            constant_val.copy_from_slice(b"expand 32-byte k");
        }

        let constant_vec = constant_val
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        Ok(ChaCha20State {
            constant: constant_vec.try_into().unwrap(),
            key: key_array,
            counter: 0u32,
            nonce,
        })
    }

    fn state(&self) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&self.constant);
        state[4..12].copy_from_slice(&self.key);

        let counter_bytes = self
            .counter
            .to_le_bytes()
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        state[12..13].copy_from_slice(&counter_bytes);
        state[13..16].copy_from_slice(&self.nonce);

        state
    }

    fn chacha_block(&self) -> [u32; 16] {
        let state: [u32; 16] = self.state();
        let mut x: [u32; 16] = self.state();

        for _ in (0..ROUNDS).step_by(2) {
            // Odd round
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);

            // Even round
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }

        x.iter_mut().enumerate().for_each(|(i, v)| {
            *v = v.wrapping_add(state[i]);
        });

        x
    }
}

impl Iterator for &mut ChaCha20State {
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
pub struct ChaCha20(#[zeroize] ChaCha20State);

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8], constant: Option<&[u8]>) -> Result<Self, InvalidLength> {
        if nonce.len() != 12 {
            return Err(InvalidLength::Nonce);
        }

        let nonce_array: [u32; 3] = nonce
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let state = ChaCha20State::new(key, nonce_array, constant)?;
        Ok(ChaCha20(state))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Output {
        // let mut ciphertext = Vec::with_capacity(plaintext.len());
        // let mut keystream = &mut self.0;
        //
        // for chunk in plaintext.chunks(64) {
        //     let keystream_block = keystream.next().unwrap();
        //     for (i, &byte) in chunk.iter().enumerate() {
        //         ciphertext.push(byte ^ keystream_block[i]);
        //     }
        // }

        let ciphertext: Vec<u8> = plaintext
            .chunks(64)
            .zip(&mut self.0)
            .flat_map(|(chunk, k)| chunk.iter().enumerate().map(move |(i, &b)| b ^ k[i]))
            .collect();

        Output(ciphertext)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output(pub Vec<u8>);

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
