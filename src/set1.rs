//! Solutions to the challenges in Set 1.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use attacks;
use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;
use utils::metrics;
use utils::xor;

/// Run the solution to Set 1 Challenge 1 (Convert hex to base64)
pub fn challenge01() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 1,");
    println!("Convert hex to base64:\n");

    // Get the hex input.
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c\
               696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("Hex input: {}", hex);

    // Convert to base-64.
    let data = Data::from_hex(hex).unwrap();
    println!("Base-64 output: {}", data.to_base64());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 2 (Fixed XOR)
pub fn challenge02() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 2,");
    println!("Fixed XOR:\n");

    // Get the hex input.
    let hex = "1c0111001f010100061a024b53535009181c";
    println!("Hex input: {}", hex);

    // Get the key.
    let key = "686974207468652062756c6c277320657965";
    println!("Key (hex): {}", key);

    // Encrypt the data.
    let data = Data::from_hex(hex).unwrap();
    let key = Data::from_hex(key).unwrap();
    let result = xor::xor(&data, &key);
    println!("Encrypted output: {}", result.to_hex());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 3 (Single-byte XOR cipher)
pub fn challenge03() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 3,");
    println!("Single-byte XOR cipher:\n");

    // Get the hex input.
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    println!("Hex input: {}", hex);

    // Find the best XOR key.
    let data = Data::from_hex(hex).unwrap();
    let (key, _) = attacks::xor::best_single_byte_key(&data);
    println!("Key (hex): {}", key.to_hex());

    // Decrypt the data.
    let plain = xor::xor(&data, &key);
    println!("Decrypted output: {}", plain.to_text());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 4 (Detect single-character XOR)
pub fn challenge04() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 4,");
    println!("Detect single-character XOR:\n");

    // Keep track of the best match so far.
    let mut best_data = Data::new();
    let mut best_key = Data::new();
    let mut best_score = 0.0;

    // Read in all of the hexstrings from file.
    let file = File::open(&Path::new("input/set1challenge4.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        let line = line_it.unwrap();

        // Check if this line provides a better match
        let data = Data::from_hex(&line).unwrap();
        let (key, score) = attacks::xor::best_single_byte_key(&data);
        if score > best_score {
            best_data = data;
            best_key = key;
            best_score = score;
        }
    }

    // Output the results
    let plain = xor::xor(&best_data, &best_key);
    println!("Correct input: {}", best_data.to_hex());
    println!("Key (hex): {}", best_key.to_hex());
    println!("Decrypted output: {}", plain.to_text());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 5 (Implement repeating-key XOR)
pub fn challenge05() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 5,");
    println!("Implement repeating-key XOR:\n");

    // Get the text input.
    let data_text = "Burning 'em, if you ain't quick and nimble\n\
                     I go crazy when I hear a cymbal";
    println!("Text input: {}", data_text);

    // Get the key.
    let key_text = "ICE";
    println!("Key (text): {}", key_text);

    // Encrypt the data.
    let data = Data::from_text(data_text);
    let key = Data::from_text(key_text);
    let result = xor::xor(&data, &key);
    println!("Encrypted output: {}", result.to_hex());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 6 (Break repeating-key XOR)
pub fn challenge06() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 6,");
    println!("Break repeating-key XOR:\n");

    // Get the base-64 input.
    let mut base64 = "".to_string();
    let file = File::open(&Path::new("input/set1challenge6.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        base64.push_str(&line_it.unwrap());
    }
    println!("Base-64 input: {}", base64);

    // Find the best repeating-XOR key.
    let data = Data::from_base64(&base64).unwrap();
    let key = attacks::xor::best_repeating_key(&data);
    println!("Key (text): {}", key.to_text());

    // Decrypt the data.
    let plain = xor::xor(&data, &key);
    println!("Decrypted output: {}", plain.to_text());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 7 (AES in ECB mode)
pub fn challenge07() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 7,");
    println!("AES in ECB mode:\n");

    // Get the base-64 input.
    let mut base64 = "".to_string();
    let file = File::open(&Path::new("input/set1challenge7.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        base64.push_str(&line_it.unwrap());
    }
    println!("Base-64 input: {}", base64);

    // Get the key.
    let key = "YELLOW SUBMARINE";
    println!("Key (text): {}", key);

    // Decrypt the data using AES-128-ECB.
    let data = Data::from_base64(&base64).unwrap();
    let key = Data::from_text(key);
    let block = BlockCipher::new(Algorithms::Aes,
                                 OperationModes::Ecb,
                                 PaddingSchemes::Pkcs7,
                                 &key)
        .unwrap();
    let plain = block.decrypt(&data).unwrap();
    println!("Decrypted output: {}", plain.to_text());

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 1 Challenge 8 (Detect AES in ECB mode)
pub fn challenge08() {

    // Print an explanatory header.
    println!("Running Set 1, Challenge 8,");
    println!("Detect AES in ECB mode:\n");

    // Read in all of the hexstrings from file.
    let file = File::open(&Path::new("input/set1challenge8.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        let line = line_it.unwrap();

        // Check if this line was encrypted using ECB.
        let data = Data::from_hex(&line).unwrap();
        if metrics::is_ecb_mode(&data, 16) {
            println!("Encrypted with ECB: {}", data.to_hex());
        }
    }

    println!("\nChallenge complete!\n");
}
