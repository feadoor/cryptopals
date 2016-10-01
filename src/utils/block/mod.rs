//! Block cipher encryption and decryption using various modes of operation.

mod aes;
mod null;

use std::fmt;
use std::error;

use utils::data::Data;
use utils::xor::xor;

/// Algorithms that can be used for the encryption and decryption of a single block.
pub enum Algorithms {
    /// The AES algorithm.
    Aes,
    /// A dummy cipher which takes blocks of the given size and does no encryption or decryption.
    Null(usize),
}

/// Block cipher modes of operation.
pub enum OperationModes {
    /// Electronic codebook (ECB) mode.
    Ecb,
    /// Cipher block chaining (CBC) mode, including initilisation vector.
    Cbc(Data),
}

/// Block cipher padding schemes.
pub enum PaddingSchemes {
    /// PKCS#7 padding.
    Pkcs7,
}

/// Errors that can arise as a result of encrypting a piece of data.
pub enum EncryptError {
    /// The initlisation vector was of the wrong length.
    IVLength,
}

/// Errors that can arise as a result of decrypting a piece of data.
pub enum DecryptError {
    /// The initialisation vector was of the wrong length.
    IVLength,
    /// The data was of an invalid size.
    DataLength,
    /// The decrypted data had invalid padding.
    Padding,
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EncryptError::*;
        match *self {
            IVLength => write!(f, "Initialisation vector has the wrong size"),
        }
    }
}

impl fmt::Debug for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl error::Error for EncryptError {
    fn description(&self) -> &str {
        use self::EncryptError::*;
        match *self {
            IVLength => "invalid iv length",
        }
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DecryptError::*;
        match *self {
            IVLength => write!(f, "Initialisation vector has the wrong size"),
            DataLength => write!(f, "The given data has an invalid length"),
            Padding => write!(f, "The decrypted data has invalid padding"),
        }
    }
}

impl fmt::Debug for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl error::Error for DecryptError {
    fn description(&self) -> &str {
        use self::DecryptError::*;
        match *self {
            IVLength => "invalid iv length",
            DataLength => "invalid data length",
            Padding => "invalid padding",
        }
    }
}

/// Trait for encrypting and decrypting a single block of bytes, to be used as the core of a
/// block cipher.
trait Cipher {
    /// Encrypt a single block of bytes.
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
    /// Decrypt a single block of bytes.
    fn decrypt(&self, input: &[u8]) -> Vec<u8>;
    /// Return the block size used by this cipher.
    fn block_size(&self) -> usize;
}

/// A generic block cipher encryptor and decryptor.
pub struct BlockCipher {
    /// The cipher used to encrypt and decrypt single blocks.
    cipher: Box<Cipher>,
    /// The operation mode for this block cipher.
    mode: OperationModes,
    /// The padding scheme for this block cipher.
    padding: PaddingSchemes,
}

impl BlockCipher {
    /// Returns a new BlockCipher which uses the given algorithm, key, operation mode and
    /// padding scheme for encryption and decryption of blocks.
    pub fn new(algorithm: Algorithms,
               mode: OperationModes,
               padding: PaddingSchemes,
               key: &Data)
               -> Result<BlockCipher, String> {
        match algorithm {
            Algorithms::Aes => {
                match aes::AesCipher::new(key.bytes()) {
                    Ok(aes) => {
                        Ok(BlockCipher {
                            cipher: Box::new(aes),
                            mode: mode,
                            padding: padding,
                        })
                    }
                    Err(err) => Err(format!("{}", err)),
                }
            }
            Algorithms::Null(size) => {
                Ok(BlockCipher {
                    cipher: Box::new(null::NullCipher::new(size)),
                    mode: mode,
                    padding: padding,
                })
            }
        }
    }

    /// Encrypts the given input data using the given mode of operation.
    pub fn encrypt(&self, input: &Data) -> Result<Data, EncryptError> {
        let data = match self.padding {
            PaddingSchemes::Pkcs7 => self.pkcs7_pad(input),
        };
        match self.mode {
            OperationModes::Ecb => self.ecb_encrypt(&data),
            OperationModes::Cbc(ref iv) => self.cbc_encrypt(&data, iv),
        }
    }

    /// Decrypts the given input data using the given mode of operation.
    pub fn decrypt(&self, input: &Data) -> Result<Data, DecryptError> {
        let data = try!(match self.mode {
            OperationModes::Ecb => self.ecb_decrypt(input),
            OperationModes::Cbc(ref iv) => self.cbc_decrypt(input, iv),
        });
        match self.padding {
            PaddingSchemes::Pkcs7 => self.pkcs7_unpad(&data),
        }
    }

    /// Encrypts the given data using ECB mode.
    fn ecb_encrypt(&self, data: &Data) -> Result<Data, EncryptError> {

        // Somewhere to store the resulting encrypted message.
        let mut output = Vec::with_capacity(data.len());

        // Iterate over the data, one block at a time, encrypting them, and storing the results.
        let mut ix = 0;
        while ix + self.cipher.block_size() <= data.len() {
            let in_block = &data.bytes()[ix..ix + self.cipher.block_size()];
            output.extend_from_slice(&self.cipher.encrypt(in_block));
            ix += self.cipher.block_size();
        }

        Ok(Data::from_bytes(output))
    }

    /// Decrypts the given data using ECB mode.
    fn ecb_decrypt(&self, data: &Data) -> Result<Data, DecryptError> {

        // Check that the data is a valid length before decrypting.
        if data.len() % self.cipher.block_size() != 0 {
            return Err(DecryptError::DataLength);
        }

        // Somewhere to store the resulting decrypted message.
        let mut output = Vec::with_capacity(data.len());

        // Iterate over the data, one block at a time, decrypting them, and storing the results.
        let mut ix = 0;
        while ix < data.len() {
            let in_block = &data.bytes()[ix..ix + self.cipher.block_size()];
            output.extend_from_slice(&self.cipher.decrypt(in_block));
            ix += self.cipher.block_size();
        }

        Ok(Data::from_bytes(output))
    }

    /// Encrypts the given data using CBC mode.
    fn cbc_encrypt(&self, data: &Data, iv: &Data) -> Result<Data, EncryptError> {

        // Check that the initialisation vector has the right length.
        if iv.len() != self.cipher.block_size() {
            return Err(EncryptError::IVLength);
        }

        // Somewhere to store the resulting encrypted message.
        let mut output = Vec::with_capacity(data.len());

        // Iterate over the data, one block at a time, XORing with the previous ciphertext block,
        // then encrypting.
        let mut ix = 0;
        let mut last_out_block = iv.clone();
        while ix + self.cipher.block_size() <= data.len() {
            let in_block = data.slice(ix, ix + self.cipher.block_size());
            let xor_block = xor(&in_block, &last_out_block);
            let out_block = self.cipher.encrypt(xor_block.bytes());
            output.extend_from_slice(&out_block);
            last_out_block = Data::from_bytes(out_block);
            ix += self.cipher.block_size();
        }

        Ok(Data::from_bytes(output))
    }

    /// Decrypts the given data using CBC mode.
    fn cbc_decrypt(&self, data: &Data, iv: &Data) -> Result<Data, DecryptError> {

        // Check that the initialisation vector has the right length.
        if iv.len() != self.cipher.block_size() {
            return Err(DecryptError::IVLength);
        }

        // Check that the data itself is of a valid length.
        if data.len() % self.cipher.block_size() != 0 {
            return Err(DecryptError::DataLength);
        }

        // Somewhere to store the resulting decrypted message.
        let mut output = Vec::with_capacity(data.len());

        // Iterate over the data, one block at a time, decrypting the block and then XORing with
        // the previous ciphertext block.
        let mut ix = 0;
        let mut last_in_block = iv.clone();
        while ix + self.cipher.block_size() <= data.len() {
            let in_block = data.slice(ix, ix + self.cipher.block_size());
            let xor_block = self.cipher.decrypt(in_block.bytes());
            let out_block = xor(&Data::from_bytes(xor_block), &last_in_block);
            output.extend_from_slice(out_block.bytes());
            last_in_block = in_block;
            ix += self.cipher.block_size();
        }

        Ok(Data::from_bytes(output))
    }

    /// Pads the given data using PKCS#7
    fn pkcs7_pad(&self, data: &Data) -> Data {

        // Work out the value of the padding bytes.
        let pad = self.cipher.block_size() - data.len() % self.cipher.block_size();

        // Construct a new Data with the padding included.
        let mut new_bytes = data.bytes().to_vec();
        for _ in 0..pad {
            new_bytes.push(pad as u8);
        }
        Data::from_bytes(new_bytes)
    }

    /// Unpads the given data using PKCS#7
    fn pkcs7_unpad(&self, data: &Data) -> Result<Data, DecryptError> {

        // Remove the last N bytes, where N is the value of the final byte, after first checking
        // that all of these bytes have value N.
        let pad = data.bytes()[data.len() - 1] as usize;
        if data.len() < pad || !(&data.bytes().ends_with(&vec![pad as u8; pad])) {
            return Err(DecryptError::Padding);
        }

        let new_bytes = &data.bytes()[..data.len() - pad];
        Ok(Data::from_bytes(new_bytes.to_vec()))
    }
}
