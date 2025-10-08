use std::fmt::{Display, LowerHex};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum RC4Error {
    WrongKeyLength(String),
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone)]
struct Prng {
    #[zeroize]
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Prng {
    pub fn new(key: &[u8]) -> Result<Self, RC4Error> {
        let mut s = [0u8; 256];
        for (i, si) in s.iter_mut().enumerate() {
            *si = i as u8;
        }

        let key_len = key.len();

        let mut j = 0usize;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key_len] as usize) % 256;
            s.swap(i, j);
        }

        Ok(Self { s, i: 0, j: 0 })
    }
}

/// Cool implementation that produces the RC4 keystream one byte at a time.
///
/// Each call to next advances the internal RC4 PRGA state (i, j, and the S permutation)
/// and returns the next keystream byte.
/// The implementation mutates the provided RC4Core (hence the &mut self):
/// repeatedly calling next continues the stream from the last state.
/// The output byte is exactly the PRGA output used for XOR with plaintext in RC4.
impl Iterator for &mut Prng {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.i = (self.i + 1) % 256;
        self.j = (self.j + self.s[self.i] as usize) % 256;
        self.s.swap(self.i, self.j);

        let si = self.s[self.i] as u32;
        let sj = self.s[self.j] as u32;
        let t = (si + sj) as usize % 256;
        Some(self.s[t])
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone)]
pub struct RC4 {
    #[zeroize]
    core: Prng,
}

impl RC4 {
    pub fn new(key: &[u8]) -> Result<Self, RC4Error> {
        let key_len = key.len();
        if !(1..=256).contains(&key_len) {
            return Err(RC4Error::WrongKeyLength(String::from(
                "Key must have 1 <= key.len() <= 256",
            )));
        }

        let core = Prng::new(key)?;

        Ok(Self { core })
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Output {
        Output(
            input
                .iter()
                .zip(&mut self.core)
                .map(|(&b, k)| b ^ k)
                .collect(),
        )
    }

    // should be more idiomatic (i.e. [Result] instead of .unwrap()) but I'm tired boss
    pub fn decrypt(key: &[u8], input: &[u8]) -> Output {
        let mut rc4 = RC4::new(key).unwrap();
        rc4.encrypt(input)
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
