//! Solutions to the challenges in Set 2.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rand;
use rand::Rng;

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

    // Write the oracle function. This oracle returns a pair - the encrypted
    // Data, and a bool indicated whether or not ECB mode was used for the
    // encryption.
    fn enc_oracle(input: &Data) -> (Data, bool) {

        // Generate a random key.
        let key = Data::random(16);

        // Decide whether to use ECB mode.
        let ecb: bool = rand::random();

        // Generate some random bytes at the start and end of the input.
        let mut noisy_input = Vec::with_capacity(input.bytes().len() + 20);
        let before_count = rand::thread_rng().gen_range(5, 11);
        let after_count  = rand::thread_rng().gen_range(5, 11);
        let before_data  = Data::random(before_count);
        let after_data   = Data::random(after_count);

        noisy_input.extend_from_slice(before_data.bytes());
        noisy_input.extend_from_slice(input.bytes());
        noisy_input.extend_from_slice(after_data.bytes());
        let noisy_data = Data::from_bytes(noisy_input);

        // Create the BlockCipher to perform the encryption. Generate a random
        // IV for CBC mode.
        let block;
        if ecb {
            block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &key).unwrap();
        }
        else {
            let iv = Data::random(16);
            block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Cbc(iv),
                                     PaddingSchemes::Pkcs7,
                                     &key).unwrap();
        }

        // Return the encrypted Data and the bool `ecb`.
        (block.encrypt(&noisy_data), ecb)
    }

    // Run 100 trials - for each one, try encrypt some data with repeated
    // blocks using the encryption oracle, and try to accurately predict if it
    // is using ECB or CBC.
    println!("Performing trials...");
    let input = Data::from_bytes(vec![b'a'; 256]);
    let mut score = 0.0;
    for _ in 0..1000 {
        let (encrypted, answer) = enc_oracle(&input);
        let guess = metrics::is_ecb_mode(&encrypted, 16);
        if guess == answer {
            score += 1.0;
        }
    }

    // Print out how well we did.
    println!("Correctly guessed mode with a {}% success rate", score / 10.0);

    println!("\nChallenge complete!\n");
}