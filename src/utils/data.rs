//! Structure to hold the contents of a message, supporting input and output
//! of messages in a variety of formats.

pub use self::FromHexError::*;
pub use self::FromBase64Error::*;

use std::fmt;
use std::error;
use std::string::String;

/// Errors that can arise when parsing a hexadecimal string as bytes.
pub enum FromHexError {
    /// The input contained a non-hexadecimal character.
    BadHexChar(usize, char),
    /// The input had an invalid length.
    BadHexLength
}

impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BadHexChar(ix, ch) =>
                write!(f, "Invalid character {} at position {}", ch, ix),
            BadHexLength =>
                write!(f, "Invalid input length")
        }
    }
}

impl fmt::Debug for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl error::Error for FromHexError {
    fn description(&self) -> &str {
        match *self {
            BadHexChar(_, _) => "invalid character",
            BadHexLength     => "invalid length"
        }
    }
}

/// Errors that can arise when parsing a base-64 string as bytes.
pub enum FromBase64Error {
    /// The input contained an invalid character.
    BadBase64Char(usize, char),
    /// The input had an invalid length.
    BadBase64Length
}

impl fmt::Display for FromBase64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BadBase64Char(ix, ch) =>
                write!(f, "Invalid character {} at position {}", ch, ix),
            BadBase64Length =>
                write!(f, "Invalid input length")
        }
    }
}

impl fmt::Debug for FromBase64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl error::Error for FromBase64Error {
    fn description(&self) -> &str {
        match *self {
            BadBase64Char(_, _) => "invalid character",
            BadBase64Length     => "invalid length"
        }
    }
}

/// Structure which holds the contents of a message.
pub struct Data {
    /// The message as a sequence of raw bytes.
    bytes: Vec<u8>
}

impl Data {

    /// Creates a new empty Data object.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::new();
    /// ```
    pub fn new() -> Data {
        Data{bytes: Vec::new()}
    }

    /// Creates a new Data object from a sequence of bytes given as a
    /// hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns `Err(BadHexChar)` if the input contained a non-hexadecimal
    /// character.
    ///
    /// Returns `Err(BadHexLength)` if the input did not split exactly into
    /// a sequence of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_hex("536f6d6520686578").unwrap();
    /// ```
    pub fn from_hex(input: &str) -> Result<Data, FromHexError> {

        // Create a new vector which is capable of holding the sequence of
        // bytes which we parse.
        let mut bytes = Vec::with_capacity(input.len() / 2);

        // Iterate over the characters of the input string, parsing them in
        // pairs.
        let mut next_byte: u8 = 0;
        let mut parity = 0;
        for (ix, ch) in input.chars().enumerate() {

            // Read the character and attempt to parse it as a hex digit.
            let nibble = ch.to_digit(16);
            match nibble {
                Some(val) => next_byte = (next_byte << 4) | val as u8,
                None      => return Err(BadHexChar(ix, ch))
            }

            // Push the next byte onto the vector if necessary.
            parity = parity + 1;
            if parity == 2 {
                parity = 0;
                bytes.push(next_byte);
            }
        }

        // Check that we have read an even number of characters in total.
        match parity {
            0 => Ok(Data{bytes: bytes}),
            _ => Err(BadHexLength)
        }
    }

    /// Creates a new Data object from a base-64 encoded string.
    ///
    /// # Errors
    ///
    /// Returns `Err(BadBase64Char)` if an invalid character was found.
    ///
    /// Returns `Err(BadBase64Length)` if the input had an invalid length.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_base64("SSdtIGtpbGxpbmcgeW91").unwrap();
    /// ```
    pub fn from_base64(input: &str) -> Result<Data, FromBase64Error> {

        // Create a new vector which is capable of holding the sequence of
        // bytes which is produced.
        let mut bytes = Vec::with_capacity(3 * input.len() / 4);

        // Iterate over the characters of the input string, parsing them in
        // groups of four.
        let mut next_bytes: u32 = 0;
        let mut cycle = 0;
        let mut last_ix = 0;
        for (ix, ch) in input.bytes().enumerate() {

            // Read the character and convert it to a sextet to be stored on
            // the end of `next_bytes`.
            next_bytes <<= 6;
            match ch {
                b'A'...b'Z' => next_bytes |= (ch - b'A') as u32,
                b'a'...b'z' => next_bytes |= (ch - b'a' + 26) as u32,
                b'0'...b'9' => next_bytes |= (ch - b'0' + 52) as u32,
                b'+'       => next_bytes |= (ch - b'+' + 62) as u32,
                b'/'       => next_bytes |= (ch - b'/' + 63) as u32,
                b'='       => {
                    last_ix = ix;
                    break;
                },
                _          => {
                    let ch = input[ix..].chars().next().unwrap();
                    return Err(BadBase64Char(ix, ch));
                }
            }

            // Push the resulting bytes onto the end of the `bytes` vector
            // if necessary.
            cycle += 1;
            if cycle == 4 {
                cycle = 0;
                bytes.push((next_bytes >> 16) as u8);
                bytes.push((next_bytes >>  8) as u8);
                bytes.push((next_bytes >>  0) as u8);
            }
        }

        // Check that the padding is well-formed, and push the last few bytes
        // onto the end of the string.
        next_bytes >>= 6;
        match cycle {
            0 => {},
            2 => {
                if input[last_ix..].len() == 1 {
                    return Err(BadBase64Length);
                }
                if &input[last_ix..last_ix+2] != "==" {
                    let ch = input[last_ix+1..].chars().next().unwrap();
                    return Err(BadBase64Char(last_ix + 1, ch));
                }
                if input[last_ix..].len() != 2 {
                    let ch = input[last_ix+2..].chars().next().unwrap();
                    return Err(BadBase64Char(last_ix + 2, ch));
                }
                bytes.push((next_bytes >> 4) as u8)
            }
            3 => {
                if input[last_ix..].len() != 1 {
                    let ch = input[last_ix+1..].chars().next().unwrap();
                    return Err(BadBase64Char(last_ix + 1, ch));
                }
                bytes.push((next_bytes >> 10) as u8);
                bytes.push((next_bytes >>  2) as u8)
            }
            _ => return Err(BadBase64Char(last_ix, '='))
        }

        Ok(Data{bytes: bytes})
    }

    /// Creates a new Data object from a sequence of byte values represented
    /// as a plain text string.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// ```
    pub fn from_text(input: &str) -> Data {
        Data{bytes: input.as_bytes().to_vec()}
    }

    /// Creates a new Data object from a sequence of raw byte values.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_bytes(vec![100, 97, 119]);
    /// ```
    pub fn from_bytes(input: Vec<u8>) -> Data {
        Data{bytes: input}
    }

    /// Creates a new Data object representing a single byte.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_single_byte(100);
    /// ```
    pub fn from_single_byte(input: u8) -> Data {
        Data{bytes: vec![input]}
    }

    /// Returns the message as a hexadecimal string.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// let hex = data.to_hex();
    /// ```
    pub fn to_hex(&self) -> String {

        // Create a mapping from nibbles to hex characters.
        let hex_chars = b"0123456789abcdef";

        // Create a vector which will hold the byte-values of the characters
        // that should appear in the hexadecimal representation.
        let mut out_chars = Vec::with_capacity(self.bytes.len() / 2);

        // Iterate over the bytes of the message and find the hexadecimal
        // equivalent.
        for byte in &self.bytes {
            out_chars.push(hex_chars[(byte >> 4) as usize]);
            out_chars.push(hex_chars[(byte & 0xF) as usize]);
        }

        // Turn the output into a String before returning it.
        String::from_utf8(out_chars).unwrap()
    }

    /// Returns the message as a base-64 encoded string.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// let base64 = data.to_base64();
    /// ```
    pub fn to_base64(&self) -> String {

        // Create a mapping from sextets to base-64 characters.
        let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                          abcdefghijklmnopqrstuvwxyz\
                          0123456789+/";

        // Create a vector which will hold the byte-values of the characters
        // that should appear in the base-64 representation.
        let mut out_chars = Vec::with_capacity((self.bytes.len() + 2) / 3 * 4);

        // Iterate over the bytes of the message, taking them in groups of
        // three to produce four characters of output.
        let mut cycle = 0;
        let mut sextets: u32 = 0;
        for byte in &self.bytes {
            sextets = (sextets << 8) | *byte as u32;
            cycle += 1;
            if cycle == 3 {
                out_chars.push(b64_chars[((sextets >> 18) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >> 12) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >>  6) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >>  0) & 0x3F) as usize]);
                cycle = 0;
            }
        }

        // Deal with padding and the last few bytes if necessary
        match cycle {
            0 => {},
            1 => {
                sextets <<= 4;
                out_chars.push(b64_chars[((sextets >> 6) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >> 0) & 0x3F) as usize]);
                out_chars.push(b'=');
                out_chars.push(b'=');
            }
            2 => {
                sextets <<= 2;
                out_chars.push(b64_chars[((sextets >> 12) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >>  6) & 0x3F) as usize]);
                out_chars.push(b64_chars[((sextets >>  0) & 0x3F) as usize]);
                out_chars.push(b'=');
            }
            _ => panic!("Maths is broken, the end is nigh")
        }

        // Turn the output into a String before returning it.
        String::from_utf8(out_chars).unwrap()
    }

    /// Returns the message as a plain text string.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// let text = data.to_text();
    /// ```
    pub fn to_text(&self) -> String {
        String::from_utf8(self.bytes.clone()).unwrap()
    }

    /// Returns a slice containing the sequence of bytes stored in this Data
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// let bytes = data.bytes();
    /// ```
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a new Data formed of a slice of the sequence of bytes stored
    /// in this Data.
    ///
    /// # Example
    ///
    /// ```
    /// let data = Data::from_text("Some text");
    /// let slice = data.slice(3, 7);
    /// ```
    pub fn slice(&self, start: usize, end: usize) -> Data {
        Data{bytes: self.bytes[start..end].to_vec()}
    }
}