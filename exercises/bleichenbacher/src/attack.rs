#![allow(dead_code)]
#![allow(non_snake_case)]

use std::u128;

use hex::ToHex;
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use rand::Rng;
use reqwest::blocking::Client;
use serde_json::Value;

use crate::utils::{CustomError, DecryptRes, EncryptRes, PublicKeyInfo};

#[derive(Debug)]
pub struct Attacker {
    pub client: Client,
    pub url: String,
    pub c_bytes: Vec<u8>,
    pub state: AttackState,
    pub timing_threshold: u128,
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

        let timing_threshold = 0u128;

        Ok(Self {
            client,
            url: String::from(url),
            c_bytes: c,
            state,
            timing_threshold,
        })
    }

    pub fn calibrate_timing(&self, repeats: u32) -> Result<u128, CustomError> {
        let trials = 5usize;
        let mut valid_times = Vec::new();
        for _ in 0..trials {
            let res = self.decrypt(&self.c_bytes, Some(repeats))?;
            valid_times.push(res.time_ns);
        }
        let valid_mean = valid_times.iter().copied().sum::<u128>() / (valid_times.len() as u128);

        // measure several invalid ciphertexts (flip one byte or random)
        let mut invalid_times = Vec::new();
        for _ in 0..trials {
            let mut rng = rand::rng();
            let mut bad = self.c_bytes.clone();

            let idx = rng.random_range(0..bad.len());
            bad[idx] ^= 0xff;
            let res = self.decrypt(&bad, Some(repeats))?;
            invalid_times.push(res.time_ns);
        }
        let invalid_mean = invalid_times.iter().copied().sum::<u128>() / (invalid_times.len() as u128);

        println!("calibrate: valid_mean={} ns, invalid_mean={} ns", valid_mean, invalid_mean);

        // choose midpoint as threshold
        let threshold = (valid_mean + invalid_mean) / 2u128;
        Ok(threshold)
    }

    pub fn is_valid_by_timing(&self, cipher: &[u8], repeats: u32) -> Result<bool, CustomError> {
        let res = self.decrypt(cipher, Some(repeats))?;
        let t = res.time_ns;
        let threshold = self.timing_threshold;
        Ok(t < threshold)
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

    /// Step 1 can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext.
    pub fn bleichenbacher_attack(&mut self) -> Result<Vec<u8>, CustomError> {
        println!("Calibrating timing");
        self.timing_threshold = self.calibrate_timing(1000)?;
        println!("Timing threshold set to {} ns", self.timing_threshold);

        let mut si = self.step2a()?;

        let mut it = 0u64;
        loop {
            println!("Iteration {}: M = {:?}, si = {}", it, self.state.M, si);
            it += 1;

            if self.state.M.len() >= 2 {
                si = self.step2b(&si)?;
            } else if self.state.M.len() == 1 {
                if self.state.M[0].0 == self.state.M[0].1 {
                    // only one interval left with a == b
                    return self.step4(&si).map(|m| {
                        let mut m_bytes = m.to_bytes_be();

                        while m_bytes.len() < self.state.k {
                            m_bytes.insert(0, 0u8);
                        }
                        m_bytes
                    });
                } else {
                    si = self.step2c(&si)?;
                }
            } else {
                return Err(CustomError::Other(
                    "No intervals left in M".to_string(),
                ));
            }

            println!("Found si = {}", si);

            self.step3(&si);
        }
    }

    fn step2a(&mut self) -> Result<BigUint, CustomError> {
        // let mut s = (&self.state.n + 3u8 * &self.state.B - 1u8) / (3u8 * &self.state.B);
        let mut s = div_ceil(&self.state.n, &(3u8 * &self.state.B));
        loop {
            let c_prime = (&self.state.c * s.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);

            println!("Trying c_prime: {}", hex::encode(&c_prime_bytes));
            if self.is_valid_by_timing(&c_prime_bytes, 1000)? {
                return Ok(s);
            }
            s += 1u8;
        }
    }

    fn step2b(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let mut si = prev_s + 1u8;
        loop {
            let c_prime = (&self.state.c * si.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);
            if self.is_valid_by_timing(&c_prime_bytes, 1000)? {
                return Ok(si);
            }
            si += 1u8;
        }
    }

    fn step2c(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let (a, b) = &self.state.M[0].clone();

        let mut ri = 2u8 * (prev_s * b - 2u8 * &self.state.B) / &self.state.n;
        loop {
            let mut si = (&self.state.B + &ri * &self.state.n) / b;

            while si < (3u8 * &self.state.B + &ri * &self.state.n) / a {
                let c_prime =
                    (&self.state.c * si.modpow(&self.state.e, &self.state.n)) % &self.state.n;
                let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);

                if self.is_valid_by_timing(&c_prime_bytes, 1000)? {
                    return Ok(si);
                }
                si += 1u8;
            }

            ri += 1u8;
        }
    }

    fn step3(&mut self, si: &BigUint) {
        let mut new_M = Vec::<(BigUint, BigUint)>::new();

        for (a, b) in &self.state.M {
            let r_lower = div_ceil(&(a * si - 3u8 * &self.state.B), &self.state.n);
            // let r_upper = (b * si - 2u8 * &self.state.B) / &self.state.n;
            let r_upper = div_ceil(&(b * si - 2u8 * &self.state.B), &self.state.n);

            let mut r = r_lower.clone();
            while r <= r_upper {
                let lower_bound = std::cmp::max(
                    a.clone(),
                    (2u8 * &self.state.B + &r * &self.state.n + si - 1u8) / si,
                );
                let upper_bound = std::cmp::min(
                    b.clone(),
                    (3u8 * &self.state.B - 1u8 + &r * &self.state.n) / si,
                );

                if lower_bound <= upper_bound {
                    new_M.push((lower_bound, upper_bound));
                }
                r += 1u8;
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

fn to_k_bytes_be(x: &BigUint, k: usize) -> Vec<u8> {
    // let mut x_bytes = x.to_bytes_be();
    // while x_bytes.len() < k {
    //     x_bytes.insert(0, 0u8);
    // }
    // x_bytes
    let x_bytes = x.to_bytes_be();
    if x_bytes.len() < k {
        let mut padded = vec![0u8; k - x_bytes.len()];
        padded.extend_from_slice(&x_bytes);
        padded
    } else {
        x_bytes
    }
}

#[derive(Debug)]
pub struct AttackState {
    pub k: usize,
    pub n: BigUint,
    pub B: BigUint,
    pub c: BigUint,
    pub M: Vec<(BigUint, BigUint)>,
    pub e: BigUint,
}

impl AttackState {
    pub fn new(rsa_pubkey: PublicKeyInfo, c: &[u8]) -> Self {
        let k = rsa_pubkey.public_key_size_bits / 8;

        let decoded = hex::decode(&rsa_pubkey.public_modulus_hex).expect("Invalid hex in modulus");
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
