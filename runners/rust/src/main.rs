use cyphera::Client;
use cyphera::alphabet::Alphabet;
use cyphera::ff1::core::FF1;
use cyphera::ff3::core::FF3;
use cyphera::keys::{KeyRecord, KeyStatus, MemoryProvider};
use cyphera::policy::{PolicyEntry, PolicyFile};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() {
    let input_dir = std::env::args().nth(1).unwrap_or_else(|| "inputs".to_string());
    let output_dir = std::env::args().nth(2).unwrap_or_else(|| "results/rust".to_string());

    // Engine tests
    let engine_in = Path::new(&input_dir).join("engine");
    let engine_out = Path::new(&output_dir).join("engine");
    if engine_in.exists() {
        fs::create_dir_all(&engine_out).unwrap();
        for entry in fs::read_dir(&engine_in).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                println!("[engine] {}", name);
                let input: Value = serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();
                let result = run_engine(&input);
                fs::write(engine_out.join(&name), serde_json::to_string_pretty(&result).unwrap()).unwrap();
            }
        }
    }

    // SDK tests
    let sdk_in = Path::new(&input_dir).join("sdk");
    let sdk_out = Path::new(&output_dir).join("sdk");
    if sdk_in.exists() {
        fs::create_dir_all(&sdk_out).unwrap();
        for entry in fs::read_dir(&sdk_in).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                println!("[sdk] {}", name);
                let input: Value = serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();
                let result = run_sdk(&input);
                fs::write(sdk_out.join(&name), serde_json::to_string_pretty(&result).unwrap()).unwrap();
            }
        }
    }

    println!("Done. Results in {}", output_dir);
}

fn run_engine(input: &Value) -> Value {
    let engine = input["engine"].as_str().unwrap_or("ff1");
    let global_alphabet = input["alphabet"].as_str();
    let global_key = input["key"].as_str();
    let global_tweak = input["tweak"].as_str();
    let is_nist = input.get("source").is_some();

    let cases = input["cases"].as_array().unwrap();
    let mut results = Vec::new();

    for c in cases {
        let key_hex = c["key"].as_str().or(global_key).unwrap_or("");
        let tweak_hex = c["tweak"].as_str().or(global_tweak).unwrap_or("");
        let alpha_str = c["alphabet"].as_str().or(global_alphabet).unwrap_or("0123456789");
        let plaintext = c["plaintext"].as_str().unwrap_or("");

        let mut r = c.clone();

        match run_engine_case(engine, alpha_str, key_hex, tweak_hex, plaintext) {
            Ok((encrypted, decrypted)) => {
                r["ciphertext"] = json!(encrypted);
                r["decrypted"] = json!(decrypted);
                r["roundtrip"] = json!(decrypted == plaintext);
                if is_nist {
                    if let Some(expected) = c["expected"].as_str() {
                        r["matches_nist"] = json!(encrypted == expected);
                    }
                }
                r["error"] = json!(null);
            }
            Err(e) => {
                r["ciphertext"] = json!(null);
                r["decrypted"] = json!(null);
                r["roundtrip"] = json!(false);
                r["error"] = json!(e);
            }
        }

        results.push(r);
    }

    let mut out = input.clone();
    out["results"] = json!(results);
    out["runner"] = json!("rust");
    out["sdk_version"] = json!("0.1.0-dev");
    out
}

fn run_engine_case(engine: &str, alpha_str: &str, key_hex: &str, tweak_hex: &str, plaintext: &str) -> Result<(String, String), String> {
    let key = hex::decode(key_hex).map_err(|e| format!("hex key: {}", e))?;
    let tweak = if tweak_hex.is_empty() { vec![] } else {
        hex::decode(tweak_hex).map_err(|e| format!("hex tweak: {}", e))?
    };
    let alphabet = Alphabet::new(alpha_str).map_err(|e| format!("alphabet: {}", e))?;

    match engine {
        "ff1" => {
            let cipher = FF1::new(&key, &tweak, alphabet).map_err(|e| format!("FF1::new: {}", e))?;
            let encrypted = cipher.encrypt(plaintext).map_err(|e| format!("FF1::encrypt: {}", e))?;
            let decrypted = cipher.decrypt(&encrypted).map_err(|e| format!("FF1::decrypt: {}", e))?;
            Ok((encrypted, decrypted))
        }
        "ff3" => {
            let cipher = FF3::new(&key, &tweak, alphabet).map_err(|e| format!("FF3::new: {}", e))?;
            let encrypted = cipher.encrypt(plaintext).map_err(|e| format!("FF3::encrypt: {}", e))?;
            let decrypted = cipher.decrypt(&encrypted).map_err(|e| format!("FF3::decrypt: {}", e))?;
            Ok((encrypted, decrypted))
        }
        _ => Err(format!("unknown engine: {}", engine)),
    }
}

fn run_sdk(input: &Value) -> Value {
    let cases = input["cases"].as_array().unwrap();
    let mut results = Vec::new();

    let client = if let Some(config) = input.get("config") {
        Some(build_client(config))
    } else {
        None
    };

    for c in cases {
        let policy = c["policy"].as_str().unwrap_or("test");
        let plaintext = c["plaintext"].as_str().unwrap_or("");

        let mut r = c.clone();

        match &client {
            None => {
                r["error"] = json!("no config provided");
            }
            Some(Ok(cl)) => {
                match cl.protect(policy, plaintext) {
                    Ok(result) => {
                        r["protected"] = json!(result.output);

                        let engine_type = get_engine_from_config(input, policy);

                        if engine_type == "mask" {
                            if let Some(expected) = c["expected"].as_str() {
                                r["matches_expected"] = json!(result.output == expected);
                            }
                            r["reversible"] = json!(false);
                            r["error"] = json!(null);
                        } else if engine_type == "hash" {
                            if let Ok(second) = cl.protect(policy, plaintext) {
                                r["deterministic"] = json!(result.output == second.output);
                            }
                            r["reversible"] = json!(false);
                            r["error"] = json!(null);
                        } else {
                            let tag_enabled = is_tag_enabled(input, policy);

                            if tag_enabled {
                                match cl.access_by_tag(&result.output) {
                                    Ok(accessed) => {
                                        r["accessed"] = json!(accessed.output);
                                        r["roundtrip"] = json!(accessed.output == plaintext);
                                    }
                                    Err(e) => {
                                        r["roundtrip"] = json!(false);
                                        r["error"] = json!(format!("{}", e));
                                    }
                                }
                            } else {
                                match cl.access(policy, &result.output) {
                                    Ok(accessed) => {
                                        r["accessed"] = json!(accessed.output);
                                        r["roundtrip"] = json!(accessed.output == plaintext);
                                    }
                                    Err(e) => {
                                        r["roundtrip"] = json!(false);
                                        r["error"] = json!(format!("{}", e));
                                    }
                                }
                            }

                            // Also test explicit access
                            match cl.access(policy, &result.output) {
                                Ok(accessed) => {
                                    r["accessed_explicit"] = json!(accessed.output);
                                    r["roundtrip_explicit"] = json!(accessed.output == plaintext);
                                }
                                Err(_) => {}
                            }

                            if !r.as_object().unwrap().contains_key("error") || r["error"].is_null() {
                                r["error"] = json!(null);
                            }
                        }
                    }
                    Err(e) => {
                        r["protected"] = json!(null);
                        r["roundtrip"] = json!(false);
                        r["error"] = json!(format!("{}", e));
                    }
                }
            }
            Some(Err(e)) => {
                r["error"] = json!(format!("client build error: {}", e));
            }
        }

        results.push(r);
    }

    let mut out = input.clone();
    out["results"] = json!(results);
    out["runner"] = json!("rust");
    out["sdk_version"] = json!("0.1.0-dev");
    out
}

fn build_client(config: &Value) -> Result<Client, String> {
    let policies_val = &config["policies"];
    let keys_val = &config["keys"];

    let mut policies = HashMap::new();
    if let Some(obj) = policies_val.as_object() {
        for (name, p) in obj {
            let tag_enabled = p.get("tag_enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            policies.insert(name.clone(), PolicyEntry {
                engine: p["engine"].as_str().unwrap_or("ff1").to_string(),
                alphabet: p.get("alphabet").and_then(|v| v.as_str()).map(|s| s.to_string()),
                key_ref: p.get("key_ref").and_then(|v| v.as_str()).map(|s| s.to_string()),
                tag: p.get("tag").and_then(|v| v.as_str()).map(|s| s.to_string()),
                tag_enabled,
                tag_length: p.get("tag_length").and_then(|v| v.as_u64()).unwrap_or(3) as usize,
                mode: p.get("mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                pattern: p.get("pattern").and_then(|v| v.as_str()).map(|s| s.to_string()),
                algorithm: p.get("algorithm").and_then(|v| v.as_str()).map(|s| s.to_string()),
            });
        }
    }

    let mut key_records = Vec::new();
    if let Some(obj) = keys_val.as_object() {
        for (name, k) in obj {
            let material_hex = k["material"].as_str().unwrap_or("");
            let material = hex::decode(material_hex).map_err(|e| format!("key hex: {}", e))?;
            key_records.push(KeyRecord {
                key_ref: name.clone(),
                version: 1,
                status: KeyStatus::Active,
                material,
                tweak: vec![],
            });
        }
    }

    let provider = MemoryProvider::new(key_records);
    let pf = PolicyFile { policies };
    Client::from_policy(pf, Box::new(provider)).map_err(|e| format!("{}", e))
}

fn get_engine_from_config(input: &Value, policy_name: &str) -> String {
    input["config"]["policies"][policy_name]["engine"]
        .as_str()
        .unwrap_or("ff1")
        .to_string()
}

fn is_tag_enabled(input: &Value, policy_name: &str) -> bool {
    input["config"]["policies"][policy_name]["tag_enabled"]
        .as_bool()
        .unwrap_or(true)
}
