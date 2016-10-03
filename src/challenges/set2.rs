//! Solutions to the challenges in Set 2.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use attacks;
use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;
use utils::metrics;
use victims::block::{EcbOrCbc, EcbWithSuffix, EcbUserProfile, EcbWithAffixes};

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
    let padded = block.encrypt(&data).unwrap();
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
    let plain = block.decrypt(&data).unwrap();
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

    // Run 100 trials - for each one, try encrypting some data with repeated blocks using the
    // encryption box, and try to accurately predict if it is using ECB or CBC.
    println!("Performing trials...");
    let mut score = 0.0;
    for _ in 0..1000 {
        let guess = attacks::block::is_ecb_mode(&mut ecb_cbc_box);
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
    let base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                  aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                  LCBJIGp1c3QgZHJvdmUgYnkK";
    let suffix = Data::from_base64(base64).unwrap();
    let ecb_suffix_box = EcbWithSuffix::new(suffix);

    // Determine the block size.
    let block_size;
    let base_len = ecb_suffix_box.encrypt(&Data::new()).len();
    let mut cnt = 1;
    loop {
        let bytes = vec![0; cnt];
        let input = Data::from_bytes(bytes);
        let new_len = ecb_suffix_box.encrypt(&input).len();
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
    if metrics::has_repeated_blocks(&output, block_size) {
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

/// Run the solution to Set 2 Challenge 13 (ECB cut-and-paste)
pub fn challenge13() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 13,");
    println!("ECB cut-and-paste:\n");

    // Create an ECB-user-profile black-box.
    let ecb_profile_box = EcbUserProfile::new();

    // Craft an illegitimate admin token.
    let admin_token = attacks::block::craft_ecb_admin_token(&ecb_profile_box);

    // Check that we've been successful.
    if ecb_profile_box.is_admin(&admin_token) {
        println!("Success!");
    } else {
        println!("Failure...");
    }

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 2 Challenge 14 (Byte-at-a-time ECB decryption (Harder))
pub fn challenge14() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 14,");
    println!("Byte-at-a-time ECB decryption (Harder):\n");

    // Create an ECB-with-suffix black-box.
    let base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                  aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                  LCBJIGp1c3QgZHJvdmUgYnkK";
    let suffix = Data::from_base64(base64).unwrap();
    let ecb_affixes_box = EcbWithAffixes::new(suffix);

    // Determine the block size.
    let block_size;
    let base_len = ecb_affixes_box.encrypt(&Data::new()).len();
    let mut cnt = 1;
    loop {
        let bytes = vec![0; cnt];
        let input = Data::from_bytes(bytes);
        let new_len = ecb_affixes_box.encrypt(&input).len();
        if new_len > base_len {
            block_size = new_len - base_len;
            break;
        }
        cnt += 1;
    }
    println!("Block size: {}", block_size);

    // Confirm that ECB is being used.
    let test_bytes = vec![0; block_size * 10];
    let output = ecb_affixes_box.encrypt(&Data::from_bytes(test_bytes));
    if metrics::has_repeated_blocks(&output, block_size) {
        println!("ECB mode is being used.");
    } else {
        println!("ECB mode is not being used, exiting.");
        return;
    }

    // Decode the suffix without reading it directly!
    println!("Decrypting suffix...");
    let suffix_guess = attacks::block::find_ecb_suffix_with_prefix(&ecb_affixes_box, block_size);
    if ecb_affixes_box.check_answer(&suffix_guess) {
        println!("Success!");
        println!("Suffix (text): {}", suffix_guess.to_text());
    } else {
        println!("Failure...");
    }

    println!("\nChallenge complete!\n");
}

/// Run the solution to Set 2 Challenge 15 (PKCS#7 padding validation)
pub fn challenge15() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 15,");
    println!("PKCS#7 padding validation:\n");

    // Write a simple function that will validate PKCS#7 padding.
    fn valid_padding(data: &Data) -> bool {
        let block = BlockCipher::new(Algorithms::Null(data.len()),
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &Data::new())
            .unwrap();

        match block.decrypt(data) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    // Write a simple function which will add some given padding to some text.
    fn add_padding(text: &str, padding: &[u8]) -> Data {
        let mut data_bytes = text.as_bytes().to_vec();
        data_bytes.extend_from_slice(padding);
        Data::from_bytes(data_bytes)
    }

    // Check the three test cases.
    let text = "ICE ICE BABY";

    println!("Checking valid paddings.");
    assert!(valid_padding(&add_padding(text, &[4, 4, 4, 4])));
    assert!(valid_padding(&add_padding(text, &[1])));
    println!("Passed!");

    println!("Checking invalid paddings.");
    assert!(!valid_padding(&add_padding(text, &[5, 5, 5, 5])));
    assert!(!valid_padding(&add_padding(text, &[1, 2, 3, 4])));
    println!("Passed!");

    println!("\nChallenge complete!\n");
}