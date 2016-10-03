//! Solutions to the challenges in Set 1.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use attacks;
use challenges::{ChallengeResults, ChallengeResultsBuilder};
use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;
use utils::metrics;
use utils::xor;

/// Run the solution to Set 1 Challenge 1 (Convert hex to base64).
///
/// # Outputs
///
/// `hex_in` - The input as a hexadecimal string.
///
/// `b64_out` - The output as a base-64 string.
pub fn challenge01() -> ChallengeResults {

    // Get the hex input.
    let hex_in = "49276d206b696c6c696e6720796f757220627261696e206c\
                  696b65206120706f69736f6e6f7573206d757368726f6f6d";

    // Convert to base-64.
    let data = Data::from_hex(hex_in).unwrap();
    let b64_out = data.to_base64();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(1)
        .description("Convert hex to base64")
        .output("hex_in", hex_in)
        .output("b64_out", &b64_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 2 (Fixed XOR).
///
/// # Outputs
///
/// `hex_in` - The input as a hexadecimal string.
///
/// `hex_key` - The XOR key as a hexadecimal string.
///
/// `hex_out` - The encrypted output as a hexadecimal string.
pub fn challenge02() -> ChallengeResults {

    // Get the hex input.
    let hex_in = "1c0111001f010100061a024b53535009181c";

    // Get the key.
    let hex_key = "686974207468652062756c6c277320657965";

    // Encrypt the data.
    let data = Data::from_hex(hex_in).unwrap();
    let key = Data::from_hex(hex_key).unwrap();
    let hex_out = xor::xor(&data, &key).to_hex();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(2)
        .description("Fixed XOR")
        .output("hex_in", hex_in)
        .output("hex_key", hex_key)
        .output("hex_out", &hex_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 3 (Single-byte XOR cipher).
///
/// # Outputs
///
/// `hex_in` - The encrypted input as a hexadecimal string.
///
/// `hex_key` - The XOR key as a hexadecimal string.
///
/// `text_out` - The decrypted output as a text string.
pub fn challenge03() -> ChallengeResults {

    // Get the hex input.
    let hex_in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    // Find the best XOR key.
    let data = Data::from_hex(hex_in).unwrap();
    let (key, _) = attacks::xor::best_single_byte_key(&data);
    let hex_key = key.to_hex();

    // Decrypt the data.
    let text_out = xor::xor(&data, &key).to_text();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(3)
        .description("Single-byte XOR cipher")
        .output("hex_in", hex_in)
        .output("hex_key", &hex_key)
        .output("text_out", &text_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 4 (Detect single-character XOR)
///
/// # Outputs
///
/// `hex_in` - The correct encrypted input as a hexadecimal string.
///
/// `hex_key` - The XOR key as a hexadecimal string.
///
/// `text_out` - The decrypted output as a text string.
pub fn challenge04() -> ChallengeResults {

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

    let hex_in = best_data.to_hex();
    let hex_key = best_key.to_hex();
    let text_out = xor::xor(&best_data, &best_key).to_text();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(4)
        .description("Detect single-character XOR")
        .output("hex_in", &hex_in)
        .output("hex_key", &hex_key)
        .output("text_out", &text_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 5 (Implement repeating-key XOR)
///
/// # Outputs
///
/// `text_in` - The unencrypted input as a plain text string.
///
/// `text_key` - The key as a plain text string.
///
/// `hex out` - The encrypted output as a hexadecimal string.
pub fn challenge05() -> ChallengeResults {

    // Get the text input.
    let text_in = "Burning 'em, if you ain't quick and nimble\n\
                   I go crazy when I hear a cymbal";

    // Get the key.
    let text_key = "ICE";

    // Encrypt the data.
    let data = Data::from_text(text_in);
    let key = Data::from_text(text_key);
    let hex_out = xor::xor(&data, &key).to_hex();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(5)
        .description("Implement repeating-key XOR")
        .output("text_in", text_in)
        .output("hex_key", text_key)
        .output("text_out", &hex_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 6 (Break repeating-key XOR)
///
/// # Outputs
///
/// `base64_in` - The encrypted input as a base 64 string.
///
/// `text_key` - The key as a plain text string.
///
/// `text_out` - The decrypted data as a plain text string.
pub fn challenge06() -> ChallengeResults {

    // Get the base-64 input.
    let mut base64_in = "".to_string();
    let file = File::open(&Path::new("input/set1challenge6.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        base64_in.push_str(&line_it.unwrap());
    }

    // Find the best repeating-XOR key.
    let data = Data::from_base64(&base64_in).unwrap();
    let key = attacks::xor::best_repeating_key(&data);
    let text_key = key.to_text();

    // Decrypt the data.
    let text_out = xor::xor(&data, &key).to_text();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(6)
        .description("Break repeating-key XOR")
        .output("base64_in", &base64_in)
        .output("text_key", &text_key)
        .output("text_out", &text_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 7 (AES in ECB mode)
///
/// # Outputs
///
/// `base64_in` - The encrypted input as a base 64 string.
///
/// `text_key` - The key as a plain text string.
///
/// `text_out` - The decrypted output as a plain text string.
pub fn challenge07() -> ChallengeResults {

    // Get the base-64 input.
    let mut base64_in = "".to_string();
    let file = File::open(&Path::new("input/set1challenge7.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        base64_in.push_str(&line_it.unwrap());
    }

    // Get the key.
    let text_key = "YELLOW SUBMARINE";

    // Decrypt the data using AES-128-ECB.
    let data = Data::from_base64(&base64_in).unwrap();
    let key = Data::from_text(text_key);
    let block = BlockCipher::new(Algorithms::Aes,
                                 OperationModes::Ecb,
                                 PaddingSchemes::Pkcs7,
                                 &key)
        .unwrap();
    let text_out = block.decrypt(&data).unwrap().to_text();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(7)
        .description("AES in ECB mode")
        .output("base64_in", &base64_in)
        .output("text_key", &text_key)
        .output("text_out", &text_out)
        .finalize()
}

/// Run the solution to Set 1 Challenge 8 (Detect AES in ECB mode)
///
/// # Outputs
///
/// `hex_in` - The correct encrypted input as a hexadecimal string.
pub fn challenge08() -> ChallengeResults {

    // Store all of the lines which are encrypted using ECB mode.
    let mut hex_in = "".to_string();

    // Read in all of the hexstrings from file.
    let file = File::open(&Path::new("input/set1challenge8.txt")).unwrap();
    let reader = BufReader::new(file);
    for line_it in reader.lines() {
        let line = line_it.unwrap();

        // Check if this line was encrypted using ECB.
        let data = Data::from_hex(&line).unwrap();
        if metrics::has_repeated_blocks(&data, 16) {
            hex_in.push_str(&data.to_hex());
        }
    }

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(8)
        .description("Detect AES in ECB mode")
        .output("hex_in", &hex_in)
        .finalize()
}
