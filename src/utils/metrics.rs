//! Functions for evaluating pieces of data according to various metrics.

pub use self::HammingDistanceError::*;

use std::fmt;
use std::error;

use utils::data::Data;

/// Errors that can arise when calculating the Hamming distance between two
/// pieces of data.
pub enum HammingDistanceError {
    /// The input data have unequal lengths.
    UnequalLengths
}

impl fmt::Display for HammingDistanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UnequalLengths => write!(f, "Inputs have unequal lengths")
        }
    }
}

impl fmt::Debug for HammingDistanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl error::Error for HammingDistanceError {
    fn description(&self) -> &str {
        match *self {
            UnequalLengths => "unequal input lengths"
        }
    }
}

/// Returns a numeric score representing how likely it is that a particular
/// piece of data is English text - a higher score is better.
///
/// # Example
///
/// ```
/// let data  = Data::from_text("This text should score quite highly");
/// let score = score_as_english(&data);
/// ```
pub fn score_as_english(data: &Data) -> f64 {
    // Variable to keep track of the score as we go.
    let mut score = 0 as f64;

    // Iterate over the data bytes, and for each one, update the score
    // according to how common that byte is in English text.
    for byte in data.bytes() {
        match *byte {
            b'E' | b'e'               => score += 12.70,
            b'T' | b't'               => score +=  9.06,
            b'A' | b'a'               => score +=  8.17,
            b'O' | b'o'               => score +=  7.51,
            b'I' | b'i'               => score +=  6.97,
            b'N' | b'n'               => score +=  6.75,
            b'S' | b's'               => score +=  6.33,
            b'H' | b'h'               => score +=  6.09,
            b'R' | b'r'               => score +=  5.99,
            b'D' | b'd'               => score +=  4.25,
            b'L' | b'l'               => score +=  4.03,
            b'C' | b'c'               => score +=  2.78,
            b'U' | b'u'               => score +=  2.76,
            b'M' | b'm'               => score +=  2.41,
            b'W' | b'w'               => score +=  2.36,
            b'F' | b'f'               => score +=  2.23,
            b'G' | b'g'               => score +=  2.02,
            b'Y' | b'y'               => score +=  1.97,
            b'P' | b'p'               => score +=  1.93,
            b'B' | b'b'               => score +=  1.49,
            b'V' | b'v'               => score +=  0.98,
            b'K' | b'k'               => score +=  0.77,
            b'J' | b'j'               => score +=  0.15,
            b'X' | b'x'               => score +=  0.15,
            b'Q' | b'q'               => score +=  0.10,
            b'Z' | b'z'               => score +=  0.07,
            b' '                      => score +=  13.0,
            0x21...0x40               => score +=  0.5,
            0x00...0x08 | 0x14...0x1F => score += -10.0,
            _                         => score += -1.0
        }
    }

    score / data.bytes().len() as f64
}

/// Calculates the Hamming distance between two pieces of data of equal size.
///
/// # Errors
///
/// Returns `Err(UnequalLengths)` when the input lengths differ.
/// # Example
///
/// ```
/// let data1 = Data::from_text("Some text");
/// let data2 = Data::from_text("More text");
/// let dist = hamming_distance(&data1, &data2).unwrap();
/// ```
pub fn hamming_distance(data1: &Data, data2: &Data) ->
                                            Result<u32, HammingDistanceError> {

    // Check that the two inputs have equal sizes.
    if data1.bytes().len() != data2.bytes().len() {
        return Err(UnequalLengths);
    }

    // Now calculate the Hamming distance.
    let mut dist = 0;
    for (byte1, byte2) in data1.bytes().iter().zip(data2.bytes().iter()) {
        let mut xor_byte = *byte1 ^ *byte2;
        let mut bitcount = 0;
        while xor_byte != 0 {
            bitcount += 1;
            xor_byte &= xor_byte - 1;
        }
        dist += bitcount;
    }

    Ok(dist)
}

/// Returns a numeric score representing how likely it is that the given data
/// has been encoded using a repeating XOR key of the given size - lower is
/// better.
///
/// # Example
///
/// ```
/// let data = Data::from_text("This is a very secret message");
/// let key  = Data::from_text("key");
/// let enc  = xor(&data, &key);
///
/// let score = score_xor_keysize(&data, 3)
/// ```
pub fn score_xor_keysize(data: &Data, keysize: usize) -> f64 {

    // Iterate over pairs of blocks of data of the given length, and find the
    // average Hamming distance between blocks.
    let mut average_distance = 0.0;

    let num_pairs = data.bytes().len() / keysize - 1;
    for ix in 0..num_pairs {
        let block1 = data.slice(ix * keysize, (ix + 1) * keysize);
        let block2 = data.slice((ix + 1) * keysize, (ix + 2) * keysize);
        average_distance += hamming_distance(&block1, &block2).unwrap() as f64;
    }
    average_distance /= num_pairs as f64;

    // Normalize by the keysize for fair comparison.
    average_distance / keysize as f64
}