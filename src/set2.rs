//! Solutions to the challenges in Set 2.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use blackboxes::EcbOrCbc;
use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;
use utils::metrics;

/// Run the solution to Set 2 Challenge 9 (Implement PKCS#7 padding)
pub fn challenge09() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 9,");
    println!("Implement PKCS#7 padding:\n");

    // Get the text input.
    let text = "YELLOW SUBMARINE";
    println!("Text input: {}", text);

    // Convert to hex.
    let data = Data::from_text(text);
    println!("Hex input: {}", data.to_hex());

    // Add the padding.
    let block = BlockCipher::new(Algorithms::Null(20),
                                 OperationModes::Ecb,
                                 PaddingSchemes::Pkcs7,
                                 &Data::new()).unwrap();
    let padded = block.encrypt(&data);
    println!("Padded output: {}", padded.to_hex());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 2 Challenge 10 (Implement CBC mode)
pub fn challenge10() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 10,");
    println!("Implement CBC mode:\n");

    // Get the base-64 input.
    let mut base64 = "".to_string();
    let file = File::open(&Path::new("input/set2challenge10.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        base64.push_str(&line_it.unwrap());
    }
    println!("Base-64 input: {}", base64);

    // Get the key.
    let key = "YELLOW SUBMARINE";
    println!("Key (text): {}", key);

    // Get the IV.
    let iv = Data::from_bytes(vec![0; 16]);
    println!("IV (hex): {}", iv.to_hex());

    // Decrypt the data using AES-128-CBC.
    let data = Data::from_base64(&base64).unwrap();
    let key  = Data::from_text(key);
    let block = BlockCipher::new(Algorithms::Aes,
                                 OperationModes::Cbc(iv),
                                 PaddingSchemes::Pkcs7,
                                 &key).unwrap();
    let plain = block.decrypt(&data);
    println!("Decrypted output: {}", plain.to_text());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 2 Challenge 11 (An ECB/CBC detection oracle)
pub fn challenge11() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 11,");
    println!("An ECB/CBC detection oracle:\n");

    // Create an ECB/CBC black-box.
    let mut ecb_cbc_box = EcbOrCbc::new();

    // Run 100 trials - for each one, try encrypt some data with repeated
    // blocks using the encryption oracle, and try to accurately predict if it
    // is using ECB or CBC.
    println!("Performing trials...");
    let input = Data::from_bytes(vec![b'a'; 256]);
    let mut score = 0.0;
    for _ in 0..1000 {
        let encrypted = ecb_cbc_box.encrypt(&input);
        let guess = metrics::is_ecb_mode(&encrypted, 16);
        if ecb_cbc_box.check_answer(guess) {
            score += 1.0;
        }
    }

    // Print out how well we did.
    println!("Correctly guessed mode with a {}% success rate", score / 10.0);

    println!("\nChallenge complete!\n");
}