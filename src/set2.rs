//! Solutions to the challenges in Set 2.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use attacks;
use blackboxes::{EcbOrCbc, EcbWithSuffix, EcbUserProfile, EcbWithAffixes};
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

    // Run 100 trials - for each one, try encrypt some data with repeated blocks using the
    // encryption box, and try to accurately predict if it is using ECB or CBC.
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

/// Run the solution to Set 2 Challenge 13 (ECB cut-and-paste)
pub fn challenge13() {

    // Print an explanatory header.
    println!("Running Set 2, Challenge 13,");
    println!("ECB cut-and-paste:\n");

    // Create an ECB-user-profile black-box.
    let ecb_profile_box = EcbUserProfile::new();

    // Paste together non-admin tokens in order to create an admin token. This works by first
    // asking for the following three tokens:
    //
    //                           0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    // email@foo.com         --> email=email@foo. com&uid=10&role= user
    // noone@fakeadmin       --> email=noone@fake admin&uid=10&rol e=user
    // useless@madeup.com    --> email=useless@ma deup.com&uid=10& role=user
    //
    // If we then take the first two blocks of the first token, the second block of the second
    // token and the final block of the third token, and paste them together, we will end up with
    // the following token:
    //
    // email=email@foo.com&uid=10&role=admin&uid=10&rolrole=user
    println!("Crafting admin token...");
    let token1 = ecb_profile_box.make_token("email@foo.com");
    let token2 = ecb_profile_box.make_token("noone@fakeadmin");
    let token3 = ecb_profile_box.make_token("useless@madeup");

    let mut new_token_bytes = Vec::with_capacity(4 * 16);
    new_token_bytes.extend_from_slice(&token1.bytes()[..32]);
    new_token_bytes.extend_from_slice(&token2.bytes()[16..32]);
    new_token_bytes.extend_from_slice(&token3.bytes()[32..]);

    let admin_token = Data::from_bytes(new_token_bytes);

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
    if metrics::is_ecb_mode(&output, block_size) {
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
