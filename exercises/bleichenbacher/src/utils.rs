#![allow(dead_code)]

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug)]
pub enum CustomError {
    ReqwestError(reqwest::Error),
    SerdeError(serde_json::Error),
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

impl DecryptRes {
    pub fn is_valid_pkcs1(&self) -> bool {
        self.error.is_none()
    }
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyInfo {
    pub public_modulus_hex: String,
    pub public_key_size_bits: usize,
    #[serde(deserialize_with = "string_to_u32")]
    pub public_exponent_dec: u32,
}
