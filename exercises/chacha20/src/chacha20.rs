#![allow(dead_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum InvalidLength {
    Key,
    Constant,
    Counter,
    Nonce,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20State {
    constant: [u32; 4],

    #[zeroize]
    key: [u32; 8],
    counter: [u32; 2],
    nonce: [u32; 2],
}

impl ChaCha20State {
    pub fn new(
        key: &[u8],
        counter: &[u8],
        nonce: &[u8],
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

        // Counter
        if counter.len() != 8 {
            return Err(InvalidLength::Counter);
        }
        let mut counter_array = [0u8; 8];
        counter_array.copy_from_slice(&counter[0..8]);
        let counter_array = counter_array
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        // Nonce
        if nonce.len() != 8 {
            return Err(InvalidLength::Nonce);
        }
        let mut nonce_array = [0u8; 8];
        nonce_array.copy_from_slice(&nonce[0..8]);
        let nonce_array = nonce_array
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        Ok(ChaCha20State {
            constant: constant_vec.try_into().unwrap(),
            key: key_array,
            counter: counter_array,
            nonce: nonce_array,
        })
    }

    fn chacha_block(&mut self, input: [u32; 16]) -> [u32; 16] {
        todo!()

    }
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20(#[zeroize] ChaCha20State);

impl ChaCha20 {
    pub fn new(
        key: &[u8],
        counter: &[u8],
        nonce: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<Self, InvalidLength> {
        let state = ChaCha20State::new(key, counter, nonce, constant)?;
        Ok(ChaCha20(state))
    }
}
