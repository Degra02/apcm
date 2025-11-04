#![allow(dead_code)]
#![allow(non_snake_case)]

use num_bigint::BigUint;
use num_traits::{One, Zero};
use reqwest::blocking::Client;
use serde_json::Value;

use crate::utils::{CustomError, DecryptRes, EncryptRes, PublicKeyInfo};

#[derive(Debug)]
pub struct Attacker {
    pub client: Client,
    pub url: String,
    pub c_bytes: Vec<u8>,
    pub state: AttackState,
}

impl Attacker {
    pub fn new(url: &str, cipher: Option<&[u8]>) -> Result<Self, CustomError> {
        let client = Client::new();
        let json = client.get(url.to_string()).send()?.text()?;
        let v: Value = serde_json::from_str(&json)?;
        let public_json = &v["public"];

        let rsa_pubkey: PublicKeyInfo = serde_json::from_value(public_json.clone())?;

        let mut c = vec![];
        if let Some(cipher_bytes) = cipher {
            c.extend_from_slice(cipher_bytes);
        } else {
            let json = client
                .get(format!("{}/encrypt?p={}", url, hex::encode("attack")))
                .send()?
                .text()?;
            let v: Value = serde_json::from_str(&json)?;
            let cipher_hex = v["cipher_hex"]
                .as_str()
                .ok_or(CustomError::Other("Error getting cipher_hex".to_string()))?;
            c = hex::decode(cipher_hex)
                .map_err(|e| CustomError::Other(format!("Hex decode error: {}", e)))?;
        }

        let state = AttackState::new(rsa_pubkey, &c);

        Ok(Self {
            client,
            url: String::from(url),
            c_bytes: c,
            state,
        })
    }

    pub fn encrypt(&self, plain: &[u8], repeat: Option<u32>) -> Result<EncryptRes, CustomError> {
        let plain_hex = hex::encode(plain);
        let mut full_url = String::new();
        full_url.push_str(&self.url);
        full_url.push_str(&format!("/encrypt?p={}", plain_hex));

        if let Some(r) = repeat {
            full_url.push_str(&format!("&r={}", r));
        }

        let res: EncryptRes = self.client.get(full_url).send()?.json()?;
        Ok(res)
    }

    pub fn decrypt(&self, cipher: &[u8], repeat: Option<u32>) -> Result<DecryptRes, CustomError> {
        assert_eq!(cipher.len(), self.state.k);
        let cipher_hex = hex::encode(cipher);
        let mut full_url = String::new();
        full_url.push_str(&self.url);
        full_url.push_str(&format!("/decrypt?c={}", cipher_hex));

        if let Some(r) = repeat {
            full_url.push_str(&format!("&r={}", r));
        }

        let res: DecryptRes = self.client.get(full_url).send()?.json()?;
        Ok(res)
    }

    pub fn bleichenbacher_attack(&mut self) -> Result<Vec<u8>, CustomError> {
        // Step 2a can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext, but check
        // anyway
        let c_prime_bytes = to_k_bytes_be(&self.state.c, self.state.k);
        if !self.decrypt(&c_prime_bytes, None)?.is_valid_pkcs1() {
            return Err(CustomError::Other(
                "Initial ciphertext is not PKCS#1 v1.5 compliant".to_string(),
            ));
        }

        let mut s = self.step2a()?;

        let mut it = 1u64;
        loop {
            println!(
                "Iteration {}, si = {}, M.len(): {}",
                it,
                s,
                self.state.M.len()
            );
            it += 1;

            if self.state.M.len() >= 2 {
                s = self.step2b(&s)?;
            } else if self.state.M.len() == 1 {
                if self.state.M[0].0 == self.state.M[0].1 {
                    // only one interval left with a == b
                    return self.step4(&s).map(|m| {
                        let mut m_bytes = m.to_bytes_be();

                        while m_bytes.len() < self.state.k {
                            m_bytes.insert(0, 0u8);
                        }
                        m_bytes
                    });
                } else {
                    s = self.step2c(&s)?;
                }
            } else {
                return Err(CustomError::Other("No intervals left in M".to_string()));
            }

            println!("Found si = {}", s);

            self.state.combine_intervals();
            self.step3(&s);
        }
    }

    fn step2a(&mut self) -> Result<BigUint, CustomError> {
        let mut s = div_ceil(&self.state.n, &(&BigUint::from(3u8) * &self.state.B));

        loop {
            let c_prime = (&self.state.c * s.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);
            println!("Testing si = {}", s);
            if self.decrypt(&c_prime_bytes, None)?.is_valid_pkcs1() {
                return Ok(s);
            }
            s += BigUint::one();
        }
    }

    fn step2b(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let mut si = prev_s + BigUint::one();
        loop {
            let c_prime = (&self.state.c * si.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);
            println!("Testing si = {}", si);

            if self.decrypt(&c_prime_bytes, None)?.is_valid_pkcs1() {
                return Ok(si);
            }
            si += BigUint::one();
        }
    }

    fn step2c(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let (a, b) = &self.state.M[0];
        let two = BigUint::from(2u8);
        let three = BigUint::from(3u8);

        let mut r = div_ceil(&(&two * (b * prev_s - &two * &self.state.B)), &self.state.n);

        loop {
            // si = ceil((B + ri*n) / b)
            let mut s = div_ceil(&(&two * &self.state.B + &r * &self.state.n), b);
            // s_end = floor((3B + ri*n) / a)
            let s_end = div_ceil(&(&three * &self.state.B + &r * &self.state.n), a);

            println!("si: {}, s_end: {}", s, s_end);

            while s <= s_end {
                println!("Testing si = {}", s);
                let c_prime =
                    (&self.state.c * s.modpow(&self.state.e, &self.state.n)) % &self.state.n;
                let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);

                if self.decrypt(&c_prime_bytes, None)?.is_valid_pkcs1() {
                    return Ok(s);
                }
                s += BigUint::one();
            }

            r += BigUint::one();
        }
    }

    fn step3(&mut self, s: &BigUint) {
        let one = BigUint::from(1u8);
        let two = BigUint::from(2u8);
        let three = BigUint::from(3u8);

        let mut new_M = Vec::<Interval>::new();

        for (a, b) in &self.state.M {
            let r_lower = div_ceil(&(a * s - &three * &self.state.B + &one), &self.state.n);
            let r_upper = (b * s - &two * &self.state.B) / &self.state.n;

            let mut r = r_lower.clone();
            while r <= r_upper {
                let lower_bound = std::cmp::max(
                    a.clone(),
                    div_ceil(&(2u8 * &self.state.B + &r * &self.state.n), s),
                );
                let upper_bound = std::cmp::min(
                    b.clone(),
                    &(&three * &self.state.B - 1u8 + &r * &self.state.n) / s,
                );

                if lower_bound <= upper_bound {
                    new_M.push((lower_bound, upper_bound));
                }
                r += BigUint::one();
            }
        }

        self.state.M = new_M;
    }

    fn step4(&self, s0: &BigUint) -> Result<BigUint, CustomError> {
        let (a, _) = &self.state.M[0]; // only one interval left
        let sinv = s0.modinv(&self.state.n).ok_or(CustomError::Other(
            "Modular inverse does not exist".to_string(),
        ))?;

        Ok((a * sinv) % &self.state.n)
    }
}

pub fn div_ceil(num: &BigUint, den: &BigUint) -> BigUint {
    let quot = num / den;
    let rem = num % den;
    if rem.is_zero() {
        quot
    } else {
        quot + 1u8
    }
}

fn div_floor(num: &BigUint, den: &BigUint) -> BigUint {
    num / den
}

fn clamp_sub(a: &BigUint, b: &BigUint) -> BigUint {
    if a > b {
        a - b
    } else {
        BigUint::zero()
    }
}

fn to_k_bytes_be(x: &BigUint, k: usize) -> Vec<u8> {
    let mut x_bytes = x.to_bytes_be();
    while x_bytes.len() < k {
        x_bytes.insert(0, 0u8);
    }
    x_bytes
}

pub fn unpad_pkcs1_v15(block: &[u8]) -> Result<Vec<u8>, CustomError> {
    // Check the fixed header bytes 0x00 0x02
    // if block[0] != 0x00 || block[1] != 0x02 {
    //     return Err(CustomError::Other("Invalid PKCS#1 v1.5 padding header".into()));
    // }

    // Find the 0x00 separator after the padding string PS.
    // PS must be at least 8 bytes, so scanning starts at index 2 and the
    // earliest separator index is 2 + 8 = 10.
    let mut sep_index: Option<usize> = None;
    for i in 10..block.len() {
        if block[i] == 0x00 {
            sep_index = Some(i);
            break;
        }
    }

    let sep_index =
        sep_index.ok_or_else(|| CustomError::Other("Padding separator 0x00 not found".into()))?;

    // The message starts after the separator
    let message = block[(sep_index + 1)..].to_vec();
    Ok(message)
}

type Interval = (BigUint, BigUint);

#[derive(Debug)]
pub struct AttackState {
    pub k: usize,
    pub n: BigUint,
    pub B: BigUint,
    pub c: BigUint,
    pub M: Vec<Interval>,
    pub e: BigUint,
}

impl AttackState {
    pub fn new(rsa_pubkey: PublicKeyInfo, c: &[u8]) -> Self {
        let decoded = hex::decode(&rsa_pubkey.public_modulus_hex).expect("Invalid hex in modulus");
        let k = decoded.len();
        let n = BigUint::from_bytes_be(&decoded);
        let e = BigUint::from(rsa_pubkey.public_exponent_dec);

        // B = 2^(8*(k-2))
        let B = {
            let exp: u32 = (8 * (k - 2)) as u32;
            let base: BigUint = 2u8.into();
            base.pow(exp)
        };
        let c = BigUint::from_bytes_be(c);

        // Initial interval: [2B, 3B - 1]
        let M = vec![(2u8 * &B, 3u8 * &B - 1u8)];

        Self { k, n, B, c, M, e }
    }

    pub fn combine_intervals(&mut self) {
        self.M.sort();

        let mut combined = vec![];
        for interval_a in self.M.iter() {
            let mut found = false;

            for interval_b in combined.iter_mut() {
                if overlap(interval_a, interval_b) {
                    interval_b.0 = ((&(interval_b.0)).min(&interval_a.0)).clone();
                    interval_b.1 = ((&(interval_b.1)).max(&interval_a.1)).clone();
                    found = true;
                    break;
                }
            }

            if !found {
                combined.push(interval_a.clone());
            }
        }

        self.M = combined;
    }
}

pub fn overlap(x: &Interval, y: &Interval) -> bool {
    x.0 <= y.1 && y.0 <= x.1
}

#[test]
fn test_pkci() -> Result<(), CustomError> {
    let client = Client::new();
    let url = "http://localhost:8000";

    let json = client
        .get(format!("{}/encrypt?p={}", url, hex::encode("attack")))
        .send()?
        .text()?;
    let v: Value = serde_json::from_str(&json)?;
    let cipher_hex = v["cipher_hex"]
        .as_str()
        .ok_or(CustomError::Other("Error getting cipher_hex".to_string()))?;
    let c = hex::decode(cipher_hex)
        .map_err(|e| CustomError::Other(format!("Hex decode error: {}", e)))?;

    println!("Ciphertext: {}", cipher_hex);

    let json = client
        .get(format!("{}/decrypt?c={}", url, hex::encode(&c)))
        .send()?
        .text()?;
    let v: Value = serde_json::from_str(&json)?;
    let decrypt_res: DecryptRes = serde_json::from_value(v)?;
    println!("Decrypt response: {:?}", decrypt_res);

    Ok(())
}
