#![allow(dead_code)]

use argon2::{self, Algorithm, Argon2, Params, PasswordVerifier, Version};
use clap::{Arg, Command};
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
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use num_cpus;
use std::thread;
use std::time::{Duration, Instant};

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
    pubkey: String,
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
    // Argument parsing
    let matches = Command::new("My App")
        .version("1.0")
        .author("Author Name <author@example.com>")
        .about("Does awesome things")
        .arg(
            Arg::new("workers")
                .short('w')
                .long("workers")
                .value_name("NUMBER")
                .help("Sets the number of worker threads")
                .takes_value(true),
        )
        .get_matches();

    let num_threads = matches
        .value_of("workers")
        .map(|n| n.parse::<usize>().unwrap_or_else(|_| num_cpus::get()));

    if let Some(n) = num_threads {
        ThreadPoolBuilder::new().num_threads(n).build_global()?;
    }

    let file_path = "id.json";
    let keypair = generate_keypair(file_path)?;
    let pubkey = keypair.pubkey().to_string();

    // Output the public key
    println!("Public Key: {}", pubkey);

    let client = Client::new();

    // Initialize the global hash
    let mut global_hash = String::new();

    loop {
        // Fetch data from the server
        let response = client.get("http://xenblocks.io:4447/getblocks/lastblock")
            .send()?
            .text()?;

        // Calculate the hash of the data payload
        let mut hasher = Sha256::new();
        hasher.update(response.as_bytes());
        let current_hash = hex::encode(hasher.finalize_reset());

        // Compare the hash with the global hash
        if current_hash != global_hash {
            // Update the global hash
            global_hash = current_hash.clone();

            // Deserialize the response
            let records: Vec<BlockRecord> = serde_json::from_str(&response)?;

            // Start the timer
            let start_time = Instant::now();

            // Process the records
            let results: Vec<(u64, String, String)> = records
                .par_iter()
                .map(|record| {
                    let key = record.key.as_bytes();
                    let key_str = &record.key;
                    let hash_to_verify = &record.hash_to_verify;
                    let flag = if hash_to_verify.contains("XEN11") {
                        "XEN11"
                    } else if hash_to_verify.contains("XUNI") {
                        "XUNI"
                    } else {
                        ""
                    };

                    let verification_result = match verify_hash(key, hash_to_verify) {
                        Ok(_) => format!("Verification: Ok"),
                        Err(err) => format!("Verification failed: {}", err),
                    };
                    let block_id = record.block_id;

                    println!("hash_id: {} key: {} result: {}, target: {}", block_id, key_str, verification_result, flag);
                    (block_id, verification_result, hash_to_verify.clone())
                })
                .collect();

            // Stop the timer and print the elapsed time
            let duration = start_time.elapsed();
            println!("\nTime taken for verification: {:?}", duration);

            if results.is_empty() {
                println!("No data fetched, waiting 10 seconds before next check.");
                thread::sleep(Duration::from_secs(10));
                continue;
            }

            // Sort the results by block_id in ascending order
            let mut sorted_results = results.clone();
            sorted_results.sort_by_key(|(block_id, _, _)| *block_id);

            // Serialize sorted_results to JSON
            let serialized_sorted_results = serde_json::to_string(&sorted_results)?;
            //println!("Results: {}", serialized_sorted_results);

            // Calculate the SHA-256 hash of the serialized JSON data
            let final_hash = Sha256::digest(serialized_sorted_results.as_bytes());

            // Set the first and last block ID
            let first_block_id = sorted_results.first().map(|res| res.0).unwrap_or(0);
            let last_block_id = sorted_results.last().map(|res| res.0).unwrap_or(0);

            // Prepare the output
            let output = Output {
                first_block_id,
                last_block_id,
                final_hash: hex::encode(final_hash),
                pubkey: pubkey.clone(),
            };

            // Serialize output to JSON
            let json_output = serde_json::to_string_pretty(&output)?;
            println!("\nFinal Output:\n{}", json_output);

            // Send the output JSON via POST request to the specified URL
            let post_url = "http://xenblocks.io:5000/store_data";
            let response = client.post(post_url)
                .header("Content-Type", "application/json")
                .body(json_output.clone()) // Clone json_output here
                .send()?;

            if response.status().is_success() {
                println!("Data successfully sent to the server.");
                // Log the submitted data
                let mut log_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("voter.log")?;
                writeln!(log_file, "{}", json_output)?;
            } else {
                println!("Failed to send data to the server. Status: {}", response.status());
            }
        } else {
            println!("Waiting for hashes to be mined for 10 seconds before next check.");
        }

        // Wait for 10 seconds before the next check
        thread::sleep(Duration::from_secs(10));
    }
}
