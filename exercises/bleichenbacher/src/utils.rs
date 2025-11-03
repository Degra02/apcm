#![allow(dead_code)]

use rsa::BigUint;
use rsa::RsaPublicKey;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug)]
pub enum CustomError {
    ReqwestError(reqwest::Error),
    SerdeError(serde_json::Error),
    RsaError(rsa::errors::Error),
    Other(String),
}

impl From<reqwest::Error> for CustomError {
    fn from(err: reqwest::Error) -> Self {
        CustomError::ReqwestError(err)
    }
}

impl From<serde_json::Error> for CustomError {
    fn from(err: serde_json::Error) -> Self {
        CustomError::SerdeError(err)
    }
}

impl From<rsa::errors::Error> for CustomError {
    fn from(err: rsa::errors::Error) -> Self {
        CustomError::RsaError(err)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptRes {
    pub cipher_hex: String,

    #[serde(deserialize_with = "string_to_u32")]
    pub time_ns: u32,
}

fn string_to_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<u32>().map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptRes {
    pub error: Option<String>,
    #[serde(deserialize_with = "string_to_u32")]
    pub time_ns: u32,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyInfo {
    pub public_modulus_hex: String,
    #[serde(rename = "public_key_size_bits")]
    pub bits: usize,
    #[serde(rename = "public_exponent_dec", deserialize_with = "string_to_u32")]
    pub exp: u32,
}

impl PublicKeyInfo {
    pub fn to_rsa(&self) -> Result<RsaPublicKey, CustomError> {
        let n = BigUint::parse_bytes(self.public_modulus_hex.as_bytes(), 16)
            .ok_or(CustomError::Other("Failed to parse modulus".to_string()))?;
        let e = BigUint::from(self.exp);

        let key = RsaPublicKey::new(n, e)?;
        Ok(key)
    }
}
