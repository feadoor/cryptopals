//! Solutions to the challenges in Set 2.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use attacks;
use blackboxes::{EcbOrCbc, EcbWithSuffix};
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
                                 &Data::new())
        .unwrap();
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
    let key = Data::from_text(key);
    let block = BlockCipher::new(Algorithms::Aes,
                                 OperationModes::Cbc(iv),
                                 PaddingSchemes::Pkcs7,
                                 &key)
        .unwrap();
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
    println!("Correctly guessed with a {}% success rate", score / 10.0);

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 2 Challenge 12 (Byte-at-a-time ECB decryption (Simple))
pub fn challenge12() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 12,");
    println!("Byte-at-a-time ECB decryption (Simple):\n");

    // Create an ECB-with-suffix black-box.
    let base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                  YnkK";
    let suffix = Data::from_base64(base64).unwrap();
    let ecb_suffix_box = EcbWithSuffix::new(suffix);

    // Determine the block size.
    let block_size;
    let base_len = ecb_suffix_box.encrypt(&Data::new()).bytes().len();
    let mut cnt = 1;
    loop {
        let bytes = vec![0; cnt];
        let input = Data::from_bytes(bytes);
        let new_len = ecb_suffix_box.encrypt(&input).bytes().len();
        if new_len > base_len {
            block_size = new_len - base_len;
            break;
        }
        cnt += 1;
    }
    println!("Block size: {}", block_size);

    // Confirm that ECB is being used.
    let test_bytes = vec![0; block_size * 10];
    let output = ecb_suffix_box.encrypt(&Data::from_bytes(test_bytes));
    if metrics::is_ecb_mode(&output, block_size) {
        println!("ECB mode is being used.");
    } else {
        println!("ECB mode is not being used, exiting.");
        return;
    }

    // Decode the suffix without reading it directly!
    println!("Decrypting suffix...");
    let suffix_guess = attacks::block::find_ecb_suffix(&ecb_suffix_box, block_size);
    if ecb_suffix_box.check_answer(&suffix_guess) {
        println!("Success!");
        println!("Suffix (text): {}", suffix_guess.to_text());
    } else {
        println!("Failure...");
    }

    println!("\nChallenge complete!\n");
}
