#![allow(dead_code)]

use argon2::{self, Algorithm, Argon2, Params, PasswordVerifier, Version};
use password_hash::PasswordHash;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::signature::{Keypair, Signer};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use serde_json;
use hex;

#[derive(Deserialize)]
struct BlockRecord {
    account: String,
    block_id: u64,
    date: String,
    hash_to_verify: String,
    key: String,
}

#[derive(Serialize)]
struct Output {
    first_block_id: u64,
    last_block_id: u64,
    final_hash: String,
}

fn verify_hash(key: &[u8], hashed_password: &str) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(hashed_password)
        .map_err(|e| format!("Failed to parse hashed password: {}", e))?;
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
    argon2.verify_password(key, &parsed_hash)
        .map_err(|_| "Password verification failed.".into())
}

fn generate_keypair(file_path: &str) -> Result<Keypair, Box<dyn Error>> {
    if let Ok(mut file) = OpenOptions::new().read(true).open(file_path) {
        // Read from the file
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let private_key: Vec<u8> = serde_json::from_str(&content)?;
        Ok(Keypair::from_bytes(&private_key).expect("Failed to deserialize keypair"))
    } else {
        // Generate a new Solana keypair
        let pair = Keypair::new();
        let private_key_bytes = pair.to_bytes().to_vec();

        println!("\nid.json now has your private key, delete it to generate new one\n");

        // Serialize the private key to JSON and write it to id.json
        let json = serde_json::to_string(&private_key_bytes)?;

        let mut file = File::create(file_path)?;
        file.write_all(json.as_bytes())?;

        Ok(pair)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let file_path = "id.json";
    let keypair = generate_keypair(file_path)?;
    let pubkey = keypair.pubkey();

    // Output the public key
    println!("Public Key: {}", pubkey);

    // Existing functionality to fetch and verify blocks
    let client = Client::new();
    let url = format!("http://xenblocks.io:4447/getblocks/lastblock");
    let response = client.get(&url).send()?.text()?;

    let records: Vec<BlockRecord> = serde_json::from_str(&response)?;

    // Initialize the final hash with an empty hash (all zeros)
    let mut final_hash = Sha256::new().finalize_reset().to_vec();
    let mut first_block_id = 0;
    let mut last_block_id = 0;
    let mut first = true;

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

        if first {
            first_block_id = record.block_id;
            first = false;
        }
        last_block_id = record.block_id;

        // Perform SHA-256 hashing
        let mut hasher = Sha256::new();
        hasher.update(&final_hash);
        hasher.update(hash_to_verify.as_bytes());
        final_hash = hasher.finalize_reset().to_vec();
        print!(" CRC Hash: {} ", hex::encode(final_hash.clone()));
    }

    // Prepare the output
    let output = Output {
        first_block_id,
        last_block_id,
        final_hash: hex::encode(final_hash),
    };

    // Serialize output to JSON
    let json_output = serde_json::to_string_pretty(&output)?;
    println!("\nFinal Output:\n{}", json_output);

    Ok(())
}
