#![allow(dead_code)]

use hex_literal::hex;
use reqwest::blocking::Client;
use rsa::RsaPublicKey;
use serde_json::Value;

use crate::utils::{CustomError, DecryptRes, EncryptRes, PublicKeyInfo};

const URL: &str = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app";
const TEST_URL: &str = "http://localhost:8000";

const CIPHERTEXT: [u8; 128] = hex!("2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817");


#[derive(Debug)]
pub struct Attacker {
    client: Client,
    url: String,
    rsa_pubkey: RsaPublicKey,
}

impl Attacker {
    pub fn new(url: &str) -> Result<Self, CustomError> {
        let client = Client::new();
        let json = client
            .get(url.to_string())
            .send()?
            .text()?;

        let v: Value = serde_json::from_str(&json)?;
        let public_json = &v["public"];

        let public: PublicKeyInfo = serde_json::from_value(public_json.clone())?;

        Ok(Self {
            client,
            url: String::from(url),
            rsa_pubkey: public.to_rsa()?,
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

    pub fn bleichenbacher_attack(&self) -> Result<Vec<u8>, CustomError> {
        unimplemented!()
    }
}

#[test]
fn deserialize() -> Result<(), CustomError> {
    let attacker = Attacker::new(TEST_URL)?;
    println!("Public key: {:?}", attacker.rsa_pubkey);

    let res = attacker.encrypt("ciccio".as_bytes(), None)?;

    println!("{:?}", res);


    Ok(())
}
