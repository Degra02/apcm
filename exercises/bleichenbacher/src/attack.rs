#![allow(dead_code)]
#![allow(non_snake_case)]

use num_bigint::BigUint;
use num_traits::{One, Zero};
use reqwest::blocking::Client;
use serde_json::Value;

use crate::{utils::{CustomError, DecryptRes, EncryptRes, PublicKeyInfo}};
use crate::bytes::to_k_bytes_be;

#[derive(Debug)]
pub struct Oracle {
    pub client: Client,
    pub url: String
}

impl Oracle {
    pub fn new(url: &str) -> Self {
        let client = Client::new();
        Self {
            client,
            url: String::from(url)
        }
    }

    pub fn is_compliant(&self, cipher: &BigUint, k: usize) -> Result<bool, CustomError> {
        let cipher_bytes = to_k_bytes_be(cipher, k);
        let res: DecryptRes = self.client
            .get(format!("{}/decrypt?c={}", self.url, hex::encode(&cipher_bytes)))
            .send()?
            .json()?;
        Ok(res.is_valid_pkcs1())
    }

    pub fn encrypt(&self, plain: &[u8], repeat: Option<u32>) -> Result<EncryptRes, CustomError> {
        let plain_hex = hex::encode(plain);

        let mut full_url = format!("{}/encrypt?p={}", self.url, plain_hex);

        if let Some(r) = repeat {
            full_url.push_str(&format!("&r={}", r));
        }

        let res: EncryptRes = self.client.get(full_url).send()?.json()?;
        Ok(res)
    }

    pub fn decrypt(&self, cipher: &[u8], repeat: Option<u32>) -> Result<DecryptRes, CustomError> {
        let cipher_hex = hex::encode(cipher);
        let mut full_url = format!("{}/decrypt?c={}", self.url, cipher_hex);

        if let Some(r) = repeat {
            full_url.push_str(&format!("&r={}", r));
        }

        let res: DecryptRes = self.client.get(full_url).send()?.json()?;
        Ok(res)
    }
}


#[derive(Debug)]
pub struct Attacker {
    pub oracle: Oracle,
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
        let oracle = Oracle::new(url);

        Ok(Self {
            oracle,
            state,
        })
    }

    pub fn bleichenbacher_attack(&mut self) -> Result<Vec<u8>, CustomError> {
        // Step 1 can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext, but check
        // anyway
        if !self.oracle.is_compliant(&self.state.c, self.state.k)? {
            return Err(CustomError::Other(
                "Initial ciphertext is not PKCS#1 v1.5 compliant".to_string(),
            ));
        }

        let mut it = 1u64;
        let mut s_prev = BigUint::one();
        loop {
            let mut si = if it == 1 {
                div_ceil(&self.state.n, &(&BigUint::from(3u8) * &self.state.B))
            } else {
                &s_prev + BigUint::one()
            };

            println!(
                "Iteration {}, si = {}, M.len(): {}",
                it,
                si,
                self.state.M.len()
            );

            if it == 1 || self.state.M.len() >= 2 {
                si = self.step2a()?;
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
                    si = self.step2c(&s_prev)?;
                }
            } else {
                return Err(CustomError::Other("No intervals left in M".to_string()));
            }

            println!("Found si = {}", si);

            self.state.combine_intervals();
            self.step3(&si);

            s_prev = si;
            it += 1;
        }
    }

    // also steb2b
    fn step2a(&mut self) -> Result<BigUint, CustomError> {
        let mut s = div_ceil(&self.state.n, &(&BigUint::from(3u8) * &self.state.B));
        let mut se = s.modpow(&self.state.e, &self.state.n);

        while !self.oracle.is_compliant(&(&(&self.state.c * se) % &self.state.n), self.state.k)? {
            println!("Testing si = {}", s);
            s += BigUint::one();
            se = s.modpow(&self.state.e, &self.state.n);
        }

        Ok(s)
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

                if self.oracle.is_compliant(&c_prime, self.state.k)? {
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


    // rewrite attack on a single function
    pub fn attack(&mut self) -> Result<BigUint, CustomError> {
        // Step 1 can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext, but check
        // anyway
        if !self.oracle.is_compliant(&self.state.c, self.state.k)? {
            return Err(CustomError::Other(
                "Initial ciphertext is not PKCS#1 v1.5 compliant".to_string(),
            ));
        }

        // easier access to state variables
        let n = &self.state.n;
        let e = &self.state.e;
        let B = &self.state.B;
        let k = self.state.k;

        let c = &self.state.c;

        let two_B = 2u8 * B;
        let three_B = 3u8 * B;

        let mut m_found = false;
        let mut prev_s = BigUint::one();


        while !m_found {
            let mut s_i = if self.state.it == 1 {
                div_ceil(n, &three_B)
            } else {
                &prev_s + BigUint::one()
            };

            if self.state.it == 1 || self.state.M.len() >= 2 {
                let mut se = s_i.modpow(e, n);
                while !self.oracle.is_compliant(&((c * &se) % n), k)? {
                    println!("step2a: s_i = {}", s_i);
                    s_i += 1u8;
                    se = s_i.modpow(e, n);
                }
            } else { // just one interval in M
                // step 2c
                let (a, b) = &self.state.M[0];

                let mut r_i = div_ceil(&(2u8 * (b * &prev_s - &two_B)), n);
                s_i = div_ceil(&(&two_B + &r_i * n), b);

                let mut se = s_i.modpow(e, n);

                while !self.oracle.is_compliant(&((c * &se) % n), k)? {
                    println!("step2c: s_i = {}", s_i);
                    if s_i > div_ceil(&(&three_B + &r_i * n), a) {
                        r_i += 1u8;
                        s_i = div_ceil(&(&two_B + &r_i * n), b);
                    } else {
                        s_i += 1u8;
                    }
                    se = s_i.modpow(e, n);
                }
            }


            // step 3
            let mut new_M = Vec::<Interval>::new();
            for (a, b) in &self.state.M {
                let r_lower = div_ceil(&(a * &s_i - &three_B + 1u8), n);
                let r_upper = (b * &s_i - &two_B) / n;

                let mut r = r_lower.clone();
                while r <= r_upper {
                    let lower_bound = std::cmp::max(
                        a.clone(),
                        div_ceil(&(&two_B + &r * n), &s_i),
                    );

                    let upper_bound = std::cmp::min(
                        b.clone(),
                        &(&three_B - 1u8 + &r * n) / &s_i,
                    );

                    let interval = (lower_bound, upper_bound);

                    if two_B <= interval.0 && interval.0 <= interval.1 && interval.1 < three_B {
                        new_M.push(interval);
                    }

                    r += 1u8;
                }
            }

            new_M.sort();
            let mut combined = Vec::<Interval>::new();

            for interval_a in new_M.iter() {
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

            // loop operations
            prev_s = s_i;
            self.state.M = combined;
            self.state.it += 1;

            if self.state.M.len() == 1 && self.state.M[0].0 == self.state.M[0].1 {
                m_found = true;
            }
        }

        let (m, _) = &self.state.M[0]; // only one interval left
        println!("Found m: {}", m);

        Ok(m.clone())
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

    pub it: u64,
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

        Self { k, n, B, c, M, e, it: 1u64 }
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
