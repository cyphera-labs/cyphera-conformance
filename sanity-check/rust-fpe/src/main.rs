use fpe::ff1::{FF1, FlexibleNumeralString};
use serde_json::Value;
use std::fs;

fn main() {
    let input: Value = serde_json::from_str(&fs::read_to_string("../inputs.json").unwrap()).unwrap();
    let cases = input["cases"].as_array().unwrap();
    let mut results = Vec::new();

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let key = hex::decode(case["key"].as_str().unwrap()).unwrap();
        let tweak_hex = case["tweak"].as_str().unwrap_or("");
        let tweak = if tweak_hex.is_empty() { vec![] } else { hex::decode(tweak_hex).unwrap() };
        let radix = case["radix"].as_u64().unwrap() as u32;
        let alpha = case["alphabet"].as_str().unwrap();
        let plaintext = case["plaintext"].as_str().unwrap();

        let result = match key.len() {
            16 => run::<aes::Aes128>(&key, radix, alpha, plaintext, &tweak),
            24 => run::<aes::Aes192>(&key, radix, alpha, plaintext, &tweak),
            32 => run::<aes::Aes256>(&key, radix, alpha, plaintext, &tweak),
            _ => Err(format!("bad key length: {}", key.len())),
        };

        match result {
            Ok((ct, rt)) => {
                println!("{}: {} -> {} (roundtrip={})", name, plaintext, ct, rt);
                results.push(serde_json::json!({
                    "name": name, "plaintext": plaintext, "ciphertext": ct, "roundtrip": rt, "error": null
                }));
            }
            Err(e) => {
                println!("{}: ERROR {}", name, e);
                results.push(serde_json::json!({
                    "name": name, "plaintext": plaintext, "error": e
                }));
            }
        }
    }

    let output = serde_json::json!({ "library": "fpe 0.6.1 (crates.io)", "results": results });
    fs::write("../results-rust-fpe.json", serde_json::to_string_pretty(&output).unwrap()).unwrap();
    println!("\nResults written to results-rust-fpe.json");
}

fn run<CIPH: aes::cipher::BlockEncrypt + aes::cipher::BlockDecrypt + aes::cipher::KeyInit + aes::cipher::BlockCipher + Clone>(
    key: &[u8], radix: u32, alpha: &str, plaintext: &str, tweak: &[u8]
) -> Result<(String, bool), String> {
    let ff = FF1::<CIPH>::new(key, radix).map_err(|e| format!("{:?}", e))?;
    let digits: Vec<u16> = plaintext.chars().map(|c| alpha.find(c).ok_or("bad char").map(|i| i as u16)).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let ns = FlexibleNumeralString::from(digits);
    let ct = ff.encrypt(tweak, &ns).map_err(|e| format!("{:?}", e))?;
    let ct_digits: Vec<u16> = ct.into();
    let ct_str: String = ct_digits.iter().map(|&d| alpha.chars().nth(d as usize).unwrap()).collect();

    // Decrypt roundtrip
    let ct_ns = FlexibleNumeralString::from(ct_digits);
    let pt = ff.decrypt(tweak, &ct_ns).map_err(|e| format!("{:?}", e))?;
    let pt_digits: Vec<u16> = pt.into();
    let pt_str: String = pt_digits.iter().map(|&d| alpha.chars().nth(d as usize).unwrap()).collect();

    Ok((ct_str, pt_str == plaintext))
}
