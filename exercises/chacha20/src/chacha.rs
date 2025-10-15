#![allow(clippy::upper_case_acronyms)]

use std::fmt::{Display, LowerHex};

#[derive(Debug, Clone)]
pub enum InvalidLength {
    Key,
    Constant,
    Counter,
    Nonce,
    Other,
}

const DEFAULT_CONSTANT: [u8; 16] = *b"expand 32-byte k";

pub trait ValidRounds {}
impl ValidRounds for ConstUsize<8> {}
impl ValidRounds for ConstUsize<12> {}
impl ValidRounds for ConstUsize<20> {}
pub struct ConstUsize<const N: usize>;


pub trait ChaChaVariant {
    type Counter: Copy + Into<u64> + Counter;
    const NONCE_WORDS: usize;

    fn make_state(
        constant: &[u32; 4],
        key: &[u32; 8],
        counter: Self::Counter,
        nonce: &[u32],
    ) -> [u32; 16];
}

pub struct IETF;
impl ChaChaVariant for IETF {
    type Counter = u32;
    const NONCE_WORDS: usize = 3;

    fn make_state(
        constant: &[u32; 4],
        key: &[u32; 8],
        counter: Self::Counter,
        nonce: &[u32],
    ) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(constant);
        state[4..12].copy_from_slice(key);
        state[12] = counter;
        state[13..16].copy_from_slice(&nonce[0..3]);
        state
    }
}

pub struct Original;
impl ChaChaVariant for Original {
    type Counter = u64;
    const NONCE_WORDS: usize = 2;

    fn make_state(
        constant: &[u32; 4],
        key: &[u32; 8],
        counter: Self::Counter,
        nonce: &[u32],
    ) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(constant);
        state[4..12].copy_from_slice(key);
        state[12] = (counter & 0xFFFFFFFF) as u32;
        state[13] = (counter >> 32) as u32;
        state[14..16].copy_from_slice(&nonce[0..2]);
        state
    }
}


#[derive(Debug)]
pub struct Prng<const R: usize, V: ChaChaVariant>
where
    ConstUsize<R>: ValidRounds
    {
    constant: [u32; 4],

    key: [u32; 8],
    counter: V::Counter,
    nonce: [u32; 3],

    _variant: std::marker::PhantomData<V>,
}

impl<const R: usize, V: ChaChaVariant> Prng<R, V>
where
    ConstUsize<R>: ValidRounds,
    V::Counter: Default + Counter,
{
    pub fn new(
        key: &[u8],
        nonce: &[u8],
        counter: Option<V::Counter>,
        constant: Option<&[u8; 16]>,
    ) -> Result<Self, InvalidLength> {
        if key.len() != 32 {
            return Err(InvalidLength::Key);
        }

        if nonce.len() != V::NONCE_WORDS * 4 {
            return Err(InvalidLength::Nonce);
        }

        let key: [u32; 8] = Self::to_u32_array(key, InvalidLength::Key)?;

        let mut nonce_array = [0u32; 3];
        let nonce_converted = Self::to_u32_array::<3>(nonce, InvalidLength::Nonce)?;
        nonce_array[..V::NONCE_WORDS].copy_from_slice(&nonce_converted[..V::NONCE_WORDS]);

        let constant_bytes = constant.unwrap_or(&DEFAULT_CONSTANT);
        let constant: [u32; 4] = Self::to_u32_array(constant_bytes, InvalidLength::Constant)?;

        Ok(Self {
            constant,
            key,
            counter: counter.unwrap_or_default(),
            nonce: nonce_array,
            _variant: std::marker::PhantomData,
        })
    }

    /// constructs the state
    fn state(&self) -> [u32; 16] {
        V::make_state(&self.constant, &self.key, self.counter, &self.nonce)
    }

    /// generates a single ChaCha block
    fn chacha_block(&self) -> [u32; 16] {
        let state: [u32; 16] = self.state();
        let mut x: [u32; 16] = self.state();

        for _ in (0..R).step_by(2) {
            // Odd round
            Self::qr(&mut x, 0, 4, 8, 12);
            Self::qr(&mut x, 1, 5, 9, 13);
            Self::qr(&mut x, 2, 6, 10, 14);
            Self::qr(&mut x, 3, 7, 11, 15);

            // Even round
            Self::qr(&mut x, 0, 5, 10, 15);
            Self::qr(&mut x, 1, 6, 11, 12);
            Self::qr(&mut x, 2, 7, 8, 13);
            Self::qr(&mut x, 3, 4, 9, 14);
        }

        x.iter_mut().enumerate().for_each(|(i, v)| {
            *v = v.wrapping_add(state[i]);
        });

        x
    }

    /// quarter round function
    fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
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

    /// helper function to convert a byte slice to an array of u32
    fn to_u32_array<const N: usize>(bytes: &[u8], err: InvalidLength) -> Result<[u32; N], InvalidLength> {
        // I should be checking here but I'm going down a rabbit hole
        if bytes.len() != N * 4 {
            return Err(err);
        }
        let mut arr = [0u32; N];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            arr[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(arr)
    }
}

/// like the RC4 implementation, Iterator is implemented for the Prng
/// to enable some cool iterator functions (i.e. the encrypt and keystream methods)
impl<const R: usize, V: ChaChaVariant> Iterator for &mut Prng<R, V>
where
    ConstUsize<R>: ValidRounds,
    V::Counter: Default + Counter,
{
    type Item = [u8; 64];

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.chacha_block();

        self.counter = self.counter.wrapping_inc();

        let mut bytes = [0u8; 64];
        for (i, chunk) in bytes.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&block[i].to_le_bytes());
        }

        Some(bytes)
    }
}

/// wrapper struct for the ChaCha Prng
#[derive(Debug)]
pub struct ChaCha<const R: usize, V: ChaChaVariant>(Prng<R, V>)
where
    ConstUsize<R>: ValidRounds,
    V::Counter: std::fmt::Debug + Default + Counter;

#[allow(dead_code)]
impl<const R: usize, V: ChaChaVariant> ChaCha<R, V>
where
    ConstUsize<R>: ValidRounds,
    V::Counter: std::fmt::Debug + Default + Counter,
{
    pub fn new(
        key: &[u8],
        nonce: &[u8],
        counter: Option<V::Counter>,
        constant: Option<&[u8; 16]>,
    ) -> Result<Self, InvalidLength> {
        Ok(ChaCha(Prng::<R, V>::new(key, nonce, counter, constant)?))
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Output {
        let ciphertext: Vec<u8> = plaintext
            .chunks(64)
            .zip(&mut self.0)
            .flat_map(|(chunk, k)| chunk.iter().enumerate().map(move |(i, &b)| b ^ k[i]))
            .collect();

        Output(ciphertext)
    }

    pub fn keystream(&mut self, bits: usize) -> Vec<u8> {
        self.0.into_iter().flatten().take(bits).collect()
    }
}


/// trait shenanigans to implement wrapping_add for V::Counter
pub trait Counter: Copy + Default {
    fn wrapping_inc(self) -> Self;
    fn to_u64(self) -> u64;
}

impl Counter for u32 {
    #[inline]
    fn wrapping_inc(self) -> Self {
        self.wrapping_add(1)
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl Counter for u64 {
    #[inline]
    fn wrapping_inc(self) -> Self {
        self.wrapping_add(1)
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self
    }
}

/// usual output struct for a cleaner implementation
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
