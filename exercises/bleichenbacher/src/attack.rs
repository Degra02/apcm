#![allow(dead_code)]

use hex_literal::hex;
use reqwest::blocking::Client;
use serde::{Deserialize, Deserializer, Serialize};

const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const TEST_URL: &str = "http://localhost:8000";

const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");

#[derive(Debug)]
pub enum CustomError {
    ReqwestError(reqwest::Error),
    SerdeError(serde_json::Error),
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
    pub time_ns: u32
}


fn string_to_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<u32>().map_err(serde::de::Error::custom)
}

#[derive(Debug)]
pub struct Attacker {
    client: Client,
    url: String,
}

impl Attacker {
    pub fn new(url: &str) -> Self {
        let client = Client::new();

        Self {
            client,
            url: String::from(url)
        }
    }

    pub fn encrypt(&self, plain: &str, repeat: Option<u32>) -> Result<EncryptRes, CustomError> {
        let mut full_url = String::new();
        full_url.push_str(&self.url);
        full_url.push_str(&format!("/encrypt?p={}", plain));

        if let Some(r) = repeat {
            full_url.push_str(&format!("&r={}", r));
        }

        let res = self.client.get(full_url).send()?;
        serde_json::from_str(&res.text()?).map_err(CustomError::from)
    }

}

#[test]
fn deserialize() -> Result<(), CustomError> {
    let attacker = Attacker::new(TEST_URL);
    let res = attacker.encrypt("ciccio", None)?;

    println!("{:?}", res);

    Ok(())
}
