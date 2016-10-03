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
/// `base64_out` - The output as a base-64 string.
pub fn challenge01() -> ChallengeResults {

    // Get the hex input.
    let hex_in = "49276d206b696c6c696e6720796f757220627261696e206c\
                  696b65206120706f69736f6e6f7573206d757368726f6f6d";

    // Convert to base-64.
    let data = Data::from_hex(hex_in).unwrap();
    let base64_out = data.to_base64();

    // Return the results
    ChallengeResultsBuilder::new()
        .set(1)
        .challenge(1)
        .description("Convert hex to base64")
        .output("hex_in", hex_in)
        .output("base64_out", &base64_out)
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
        .output("text_key", text_key)
        .output("hex_out", &hex_out)
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
        .output("text_key", text_key)
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

#[cfg(test)]
mod tests {

    #[test]
    fn challenge01() {
        let results = super::challenge01();
        results.check("hex_in",
                      "49276d206b696c6c696e6720796f757220627261696e206c\
                       696b65206120706f69736f6e6f7573206d757368726f6f6d");
        results.check("base64_out",
                      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    #[test]
    fn challenge02() {
        let results = super::challenge02();
        results.check("hex_in", "1c0111001f010100061a024b53535009181c");
        results.check("hex_key", "686974207468652062756c6c277320657965");
        results.check("hex_out", "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn challenge03() {
        let results = super::challenge03();
        results.check("hex_in",
                      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        results.check("hex_key", "58");
        results.check("text_out", "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn challenge04() {
        let results = super::challenge04();
        results.check("hex_in", "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f");
        results.check("hex_key", "35");
        results.check("text_out", "Now that the party is jumping\n");
    }

    #[test]
    fn challenge05() {
        let results = super::challenge05();
        results.check("text_in",
                      "Burning 'em, if you ain't quick and nimble\n\
                       I go crazy when I hear a cymbal");
        results.check("text_key", "ICE");
        results.check("hex_out",
                      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                       a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn challenge06() {
        let results = super::challenge06();
        results.check_prefix("base64_in",
                             "HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVSBgBHVBwN\
                              RU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYGDBoXQR0BUlQwXwAg\
                              EwoFR08SSAhFTmU+Fgk4RQYFCBpGB08fWXh+amI2DB0PQQ1IBlUaGwAdQnQEHgFJGg");
        results.check("text_key", "Terminator X: Bring the noise");
        results.check_prefix("text_out",
                             "I'm back and I'm ringin' the bell \n\
                              A rockin' on the mike while the fly girls yell \n\
                              In ecstasy in the back of me");
    }

    #[test]
    fn challenge07() {
        let results = super::challenge07();
        results.check_prefix("base64_in",
                             "CRIwqt4+szDbqkNY+I0qbDe3LQz0wiw0SuxBQtAM5TDdMbjCMD/venUDW9BLPEXODbk6\
                              a48oMbAY6DDZsuLbc0uR9cp9hQ0QQGATyyCESq2NSsvhx5zKlLtzdsnfK5ED5srKjK7F\
                              z4Q38/ttd+stL/9WnDzlJvAo7WBsjI5YJc2gmAYayNfmCW2lhZE/ZLG0CBD2aPw0W4");
        results.check("text_key", "YELLOW SUBMARINE");
        results.check_prefix("text_out",
                             "I'm back and I'm ringin' the bell \n\
                              A rockin' on the mike while the fly girls yell \n\
                              In ecstasy in the back of me");
    }

    #[test]
    fn challenge08() {
        let results = super::challenge08();
        results.check("hex_in",
                      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b6\
                       41dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d\
                       9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b030\
                       8649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2\
                       c123c58386b06fba186a");
    }
}