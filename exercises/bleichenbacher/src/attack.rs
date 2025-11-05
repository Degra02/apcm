#![allow(non_snake_case)]

use num_bigint::BigUint;
use num_traits::{One, Zero};
use reqwest::blocking::Client;
use serde_json::Value;

use crate::{utils::{CustomError, DecryptRes, PublicKeyInfo}};

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

    pub fn is_pkcs1_compliant(&self, cipher: &BigUint, k: usize) -> Result<bool, CustomError> {
        let cipher_bytes = to_k_bytes_be(cipher, k);
        let res: DecryptRes = self.client
            .get(format!("{}/decrypt?c={}", self.url, hex::encode(&cipher_bytes)))
            .send()?
            .json()?;
        Ok(res.is_valid())
    }
}


#[derive(Debug)]
pub struct Attacker {
    pub oracle: Oracle,
    pub state: AttackState,
}

impl Attacker {
    pub fn new(url: &str, cipher: &[u8]) -> Result<Self, CustomError> {
        let client = Client::new();
        let json = client.get(url.to_string()).send()?.text()?;
        let v: Value = serde_json::from_str(&json)?;
        let public_json = &v["public"];

        let rsa_pubkey: PublicKeyInfo = serde_json::from_value(public_json.clone())?;

        let state = AttackState::new(rsa_pubkey, cipher);
        let oracle = Oracle::new(url);

        Ok(Self {
            oracle,
            state,
        })
    }

    // rewrite attack on a single function
    pub fn attack(&mut self) -> Result<BigUint, CustomError> {
        // Step 1 can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext, but check
        // anyway
        if !self.oracle.is_pkcs1_compliant(&self.state.c, self.state.k)? {
            return Err(CustomError::Other(
                "Initial ciphertext is not PKCS#1 v1.5 compliant".to_string(),
            ));
        }

        // easier access to state variables
        let n = self.state.n.clone();
        let e = self.state.e.clone();
        let B = self.state.B.clone();
        let k = self.state.k;

        let c = self.state.c.clone();

        let two_B = 2u8 * &B;
        let three_B = 3u8 * &B;

        let mut m_found = false;
        let mut prev_s = BigUint::one();


        while !m_found {
            let mut s_i = if self.state.it == 1 {
                div_ceil(&n, &three_B)
            } else {
                &prev_s + BigUint::one()
            };

            if self.state.it == 1 || self.state.M.len() >= 2 {
                let mut se = s_i.modpow(&e, &n);
                while !self.oracle.is_pkcs1_compliant(&((&c * &se) % &n), k)? {
                    println!("step2a: s_i = {}", s_i);
                    s_i += 1u8;
                    se = s_i.modpow(&e, &n);
                }
            } else { // just one interval in M
                // step 2c
                let (a, b) = &self.state.M[0];

                let mut r_i = div_ceil(&(2u8 * (b * &prev_s - &two_B)), &n);
                s_i = div_ceil(&(&two_B + &r_i * &n), b);

                let mut se = s_i.modpow(&e, &n);

                while !self.oracle.is_pkcs1_compliant(&((&c * &se) % &n), k)? {
                    println!("step2c: s_i = {}", s_i);
                    if s_i > div_ceil(&(&three_B + &r_i * &n), a) {
                        r_i += 1u8;
                        s_i = div_ceil(&(&two_B + &r_i * &n), b);
                    } else {
                        s_i += 1u8;
                    }
                    se = s_i.modpow(&e, &n);
                }
            }


            // step 3
            let mut new_M = Vec::<Interval>::new();
            for (a, b) in &self.state.M {
                let r_lower = div_ceil(&(a * &s_i - &three_B + 1u8), &n);
                let r_upper = (b * &s_i - &two_B) / &n;

                let mut r = r_lower.clone();
                while r <= r_upper {
                    let lower_bound = std::cmp::max(
                        a.clone(),
                        div_ceil(&(&two_B + &r * &n), &s_i),
                    );

                    let upper_bound = std::cmp::min(
                        b.clone(),
                        &(&three_B - 1u8 + &r * &n) / &s_i,
                    );

                    let interval = (lower_bound, upper_bound);

                    if two_B <= interval.0 && interval.0 <= interval.1 && interval.1 < three_B {
                        new_M.push(interval);
                    }

                    r += 1u8;
                }
            }


            self.state.combine_intervals();

            // loop operations
            prev_s = s_i;
            self.state.it += 1;

            if self.state.M.len() == 1 && self.state.M[0].0 == self.state.M[0].1 {
                m_found = true;
            }
        }

        let (m, _) = &self.state.M[0]; // only one interval left

        Ok(m.clone())
    }
}

pub fn to_k_bytes_be(x: &num_bigint::BigUint, k: usize) -> Vec<u8> {
    let mut x_bytes = x.to_bytes_be();
    while x_bytes.len() < k {
        x_bytes.insert(0, 0u8);
    }
    x_bytes
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
