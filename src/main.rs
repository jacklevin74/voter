#![allow(dead_code)]

use argon2::{self, Algorithm, Argon2, Params, PasswordVerifier, Version};
use password_hash::PasswordHash;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::error::Error;
use std::env;

#[derive(Deserialize)]
struct BlockRecord {
    account: String,
    block_id: u64,
    date: String,
    hash_to_verify: String,
    id: u64,
    key: String,
}

fn verify_hash(key: &[u8], hashed_password: &str) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(hashed_password).map_err(|e| format!("Failed to parse hashed password: {}", e))?;
    let params_str = parsed_hash.params.to_string();
    let mut m = 0;
    let mut t = 0;
    let mut p = 0;
    for param in params_str.split(',') {
        let key_value: Vec<&str> = param.split('=').collect();
        match key_value[0] {
            "m" => m = key_value[1].parse::<u32>().unwrap_or(0),
            "t" => t = key_value[1].parse::<u32>().unwrap_or(0),
            "p" => p = key_value[1].parse::<u32>().unwrap_or(0),
            _ => {}
        }
    }
    if m == 0 || t == 0 || p == 0 {
        return Err("Invalid parameters found in the hashed password.".into());
    }
    let params = Params::new(m, t, p, None).map_err(|e| format!("Failed to create Argon2 parameters: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.verify_password(key, &parsed_hash).map_err(|_| "Password verification failed.".into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let block_count = args.get(1).expect("Missing block count parameter");

    let client = Client::new();
    let url = format!("http://xenblocks.io:4447/getallblocks2/{}", block_count);
    let response = client.get(&url).send()?.text()?;

    let records: Vec<BlockRecord> = serde_json::from_str(&response)?;

    for record in records {
        let key = record.key.as_bytes();
        let hash_to_verify = &record.hash_to_verify;
        let flag = if hash_to_verify.contains("XEN11") {
            "XEN11"
        } else if hash_to_verify.contains("XUNI") {
            "XUNI"
        } else {
            ""
        };
        match verify_hash(key, hash_to_verify) {
            Ok(_) => println!("Key: {} {} - Verification: Ok", record.key, flag),
            Err(err) => println!("Key: {} {} - Verification: Failed ({})", record.key, flag, err),
        }
    }

    Ok(())
}
