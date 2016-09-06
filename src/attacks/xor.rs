//! Attacks against ciphers which use XOR as the encryption algorithm.

use std::f64;

use utils::data::Data;
use utils::metrics;
use utils::xor::xor;

/// Finds the most likely single-byte key that was used to encrypt the given
/// data.
///
/// # Example
///
/// ```
/// let data = Data::from_text("This is a top secret message");
/// let key  = Data::from_text("k");
/// let enc  = xor(&data, &key);
///
/// let (likely_key, score) = best_single_byte_key(&enc);
/// ```
pub fn best_single_byte_key(data: &Data) -> (Data, f64) {

    // Keep track of the best key so far
    let (mut best_key, mut best_score) = (Data::new(), 0.0);

    // Iterate over every possible byte for the key, and compare its score
    // with the current best score.
    for key_byte in 0..256 {
        let key = Data::from_single_byte(key_byte as u8);
        let score = metrics::score_as_english(&xor(&data, &key));
        if score > best_score {
            best_key = key;
            best_score = score;
        }
    }

    (best_key, best_score)
}

/// Finds the most likely repeating-XOR key that was used to encrypt the given
/// data.
///
/// # Example
///
/// ```
/// let data = Data::from_text("This is a top secret message");
/// let key  = Data::from_text("key");
/// let enc  = xor(&data, &key);
///
/// let likely_key = best_repeating_key(&enc);
/// ```
pub fn best_repeating_key(data: &Data) -> Data {

    // First find the most likely key size.
    let (mut best_keysize, mut best_score) = (0, f64::INFINITY);
    for keysize in 2..40 {
        let score = metrics::score_xor_keysize(&data, keysize);
        if score < best_score {
            best_keysize = keysize;
            best_score = score;
        }
    }

    // Now split the data into `keysize` streams and solve each one as if it
    // were encrypted using single-byte XOR.
    let mut key_bytes = Vec::with_capacity(best_keysize);
    for ix in 0..best_keysize {

        // Fill in the bytes of a particular stream.
        let mut stream_bytes = Vec::with_capacity(
                                        data.bytes().len() / best_keysize + 1);
        let mut position = ix;
        while position < data.bytes().len() {
            stream_bytes.push(data.bytes()[position]);
            position += best_keysize;
        }

        // Find the best key for this stream.
        let stream_data = Data::from_bytes(stream_bytes);
        let (best_key, _) = best_single_byte_key(&stream_data);
        key_bytes.push(best_key.bytes()[0]);
    }

    // Put all the key bytes together to form a single key.
    Data::from_bytes(key_bytes)
}