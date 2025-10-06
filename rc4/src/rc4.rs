use std::fmt::{Display, LowerHex};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum RC4Error {
    WrongKeyLength(String),
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct RC4Core {
    #[zeroize]
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl RC4Core {
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

/// For as many iterations as are needed, the PRGA modifies the state and outputs a byte of the keystream. In each iteration, the PRGA:
/// - increments i;
/// - looks up the ith element of S, S[i], and adds that to j;
/// - exchanges the values of S[i] and S[j], then uses the sum S[i] + S[j] (modulo 256) as an index to fetch a third element of S (the keystream value K below);
/// - then bitwise exclusive ORed (XORed) with the next byte of the message to produce the next byte of either ciphertext or plaintext.
///
/// Each element of S is swapped with another element at least once every 256 iterations.
impl Iterator for &mut RC4Core {
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

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RC4 {
    #[zeroize]
    core: RC4Core,
}

impl RC4 {
    pub fn new(key: &[u8]) -> Result<Self, RC4Error> {
        let key_len = key.len();
        if !(1..=256).contains(&key_len) {
            return Err(RC4Error::WrongKeyLength(String::from(
                "Key must have 1 <= key.len() <= 256",
            )));
        }

        let core = RC4Core::new(key)?;

        Ok(Self { core })
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Output {
        let mut output = vec![];

        for (input_val, key_byte) in input.iter().zip(&mut self.core) {
            let res = input_val ^ key_byte;
            output.push(res);
        }

        Output(output)
    }

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
        unsafe {String::from_utf8_unchecked(self.0.clone()) }
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
