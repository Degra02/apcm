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


#[test]
fn deserialize_decrypt_res() {
    let json_valid = r#"
    {
        "time_ns": "123456"
    }
    "#;

    let res_valid: DecryptRes = serde_json::from_str(json_valid).unwrap();
    assert!(res_valid.is_valid_pkcs1());
    assert_eq!(res_valid.time_ns, 123456);

    let json_invalid = r#"
    {
        "error": "Invalid padding",
        "time_ns": "654321"
    }
    "#;

    let res_invalid: DecryptRes = serde_json::from_str(json_invalid).unwrap();
    assert!(!res_invalid.is_valid_pkcs1());
    assert_eq!(res_invalid.time_ns, 654321);
}

#[test]
fn deserialize_encrypt_res() {
    let json = r#"
    {
        "cipher_hex": "abcdef123456",
        "time_ns": "789012"
    }
    "#;

    let res: EncryptRes = serde_json::from_str(json).unwrap();
    assert_eq!(res.cipher_hex, "abcdef123456");
    assert_eq!(res.time_ns, 789012);
}

#[test]
fn deserialize_public_key_info() {
    let json = r#"
    {
        "public_modulus_hex": "a1b2c3d4e5f6",
        "public_key_size_bits": 1024,
        "public_exponent_dec": "65537"
    }
    "#;

    let pk_info: PublicKeyInfo = serde_json::from_str(json).unwrap();
    assert_eq!(pk_info.public_modulus_hex, "a1b2c3d4e5f6");
    assert_eq!(pk_info.public_key_size_bits, 1024);
    assert_eq!(pk_info.public_exponent_dec, 65537);
}
