#![allow(dead_code)]
#![allow(non_snake_case)]

use num_bigint::BigUint;
use once_cell::sync::Lazy;
use reqwest::blocking::Client;
use serde_json::Value;

use crate::utils::{CustomError, DecryptRes, EncryptRes, PublicKeyInfo};

pub static ONE: Lazy<BigUint> = Lazy::new(|| BigUint::from(1u32));
pub static TWO: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u32));
pub static THREE: Lazy<BigUint> = Lazy::new(|| BigUint::from(3u32));

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
                .get(format!("{}/encrypt?p={}", url, "attack"))
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
                        // prepend leading zeros if necessary
                        while m_bytes.len() < self.state.k {
                            m_bytes.insert(0, 0u8);
                        }
                        m_bytes
                    });
                } else {
                    si = self.step2c(&si)?;
                }
            }

            println!("Found si = {}", si);

            self.step3(&si);
        }
    }

    fn step2a(&mut self) -> Result<BigUint, CustomError> {
        let mut s1 = &self.state.n / (&*THREE * &self.state.B);
        loop {
            let c_prime = (&self.state.c * s1.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            let c_prime_bytes = to_k_bytes_be(&c_prime, self.state.k);
            println!("Step 2a: trying s1 = {}", s1);
            if self.decrypt(&c_prime_bytes, None)?.is_valid_pkcs1() {
                return Ok(s1);
            } else {
                s1 += &*ONE;
            }
        }
    }

    fn step2b(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let mut si = prev_s + &*ONE;
        loop {
            let c_prime = (&self.state.c * si.modpow(&self.state.e, &self.state.n)) % &self.state.n;
            if self.decrypt(&c_prime.to_bytes_be(), None)?.is_valid_pkcs1() {
                return Ok(si);
            } else {
                si += &*ONE;
            }
        }
    }

    fn step2c(&mut self, prev_s: &BigUint) -> Result<BigUint, CustomError> {
        let a = &self.state.M[0].0;
        let b = &self.state.M[0].1;

        let mut ri = &*TWO * (prev_s * b - &*TWO * &self.state.B) / &self.state.n;
        loop {
            let mut si = (&self.state.B + &ri * &self.state.n) / b;

            while si < (&*THREE * &self.state.B + &ri * &self.state.n) / a {
                let c_prime =
                    (&self.state.c * si.modpow(&self.state.e, &self.state.n)) % &self.state.n;

                if self.decrypt(&c_prime.to_bytes_be(), None)?.is_valid_pkcs1() {
                    return Ok(si);
                } else {
                    si += &*ONE;
                }
            }

            ri += &*ONE;
        }
    }

    fn step3(&mut self, si: &BigUint) {
        let mut new_M = Vec::<(BigUint, BigUint)>::new();

        for (a, b) in &self.state.M {
            let r_lower = (a * si - &*THREE * &self.state.B + &*ONE) / &self.state.n;
            let r_upper = (b * si - &*TWO * &self.state.B) / &self.state.n;

            let mut r = r_lower.clone();
            while r <= r_upper {
                let lower_bound = std::cmp::max(
                    a.clone(),
                    (&*TWO * &self.state.B + &r * &self.state.n + si - &*ONE) / si,
                );
                let upper_bound = std::cmp::min(
                    b.clone(),
                    (&*THREE * &self.state.B - &*ONE + &r * &self.state.n) / si,
                );

                if lower_bound <= upper_bound {
                    new_M.push((lower_bound, upper_bound));
                }
                r += &*ONE;
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


fn to_k_bytes_be(x: &BigUint, k: usize) -> Vec<u8> {
    let mut x_bytes = x.to_bytes_be();
    while x_bytes.len() < k {
        x_bytes.insert(0, 0u8);
    }
    x_bytes
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

        println!("Modulus hex: {}\nModulus n: {}", rsa_pubkey.public_modulus_hex, n);

        // B = 2^(8*(k-2))
        let B = &*ONE << (8 * (k - 2));
        let c = BigUint::from_bytes_be(c);

        // Initial interval: [2B, 3B - 1]
        let M = vec![(&*TWO * &B, &*THREE * &B - &*ONE)];

        Self {
            k,
            n,
            B,
            c,
            M,
            e,
        }
    }
}
