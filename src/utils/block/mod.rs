//! Block cipher encryption and decryption using various modes of operation.

mod aes;

use utils::data::Data;

/// Algorithms that can be used for the encryption and decryption of a single
/// block.
pub enum Algorithms {
    /// The AES algorithm.
    Aes
}

/// Block cipher modes of operation.
pub enum OperationModes {
    /// Electronic cookbook (ECB) mode.
    Ecb
}

/// Block cipher padding schemes.
pub enum PaddingSchemes {
    /// PKCS#7 padding.
    Pkcs7
}

/// Trait for encrypting and decrypting a single block of bytes, to be used as
/// the core of a block cipher.
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
    cipher: Box<Cipher>
}

impl BlockCipher {

    /// Returns a new BlockCipher which uses the given algorithm and key for
    /// encryption and decryption of blocks.
    ///
    /// # Example
    ///
    /// ```
    /// let key = Data::from_text("this is a secret");
    /// let block = BlockCipher::new(Algorithms::Aes, &key);
    /// ```
    pub fn new(algorithm: Algorithms, key: &Data) -> Result<BlockCipher, String> {
        match algorithm {
            Algorithms::Aes => {
                match aes::AesCipher::new(key.bytes()) {
                    Ok(aes)  => Ok(BlockCipher{cipher: Box::new(aes)}),
                    Err(err) => Err(format!("{}", err))
                }
            }
        }
    }

    /// Encrypts the given input data using the given mode of operation.
    ///
    /// # Example
    ///
    /// ```
    /// let key = Data::from_text("this is a secret");
    /// let block = BlockCipher::new(Algorithms::Aes, &key).unwrap();
    /// let input = Data::from_text("Some very important information.");
    /// let output = block.encrypt(&input, OperationModes::Ecb, PaddingSchemes::Pkcs7);
    /// ```
    pub fn encrypt(&self, input: &Data,
                       mode: OperationModes, padding: PaddingSchemes) -> Data {
        let data; let output;
        match padding {
            PaddingSchemes::Pkcs7 => data = self.pkcs7_pad(input)
        }
        match mode {
            OperationModes::Ecb => output = self.ecb_encrypt(&data)
        }
        output
    }

    /// Decrypts the given input data using the given mode of operation.
    ///
    /// # Example
    ///
    /// ```
    /// let key = Data::from_text("this is a secret");
    /// let block = BlockCipher::new(Algorithms::Aes, &key).unwrap();
    /// let hex = "366450b83d2f4fdafa7884021ba030f73266ec2819186c2cc05c36237e0217cb";
    /// let input = Data::from_hex(hex).unwrap();
    /// let output = block.decrypt(&input, OperationModes::Ecb, PaddingSchemes::Pkcs7);
    /// ```
    pub fn decrypt(&self, input: &Data,
                       mode: OperationModes, padding: PaddingSchemes) -> Data {
        let data; let output;
        match mode {
            OperationModes::Ecb => data = self.ecb_decrypt(input)
        }
        match padding {
            PaddingSchemes::Pkcs7 => output = self.pkcs7_unpad(&data)
        }
        output
    }

    /// Encrypts the given data using ECB mode.
    fn ecb_encrypt(&self, data: &Data) -> Data {

        // Somewhere to store the resulting encrypted message.
        let mut output = Vec::with_capacity(data.bytes().len());

        // Iterate over the data, one block at a time, encrypting them, and
        // storing the results.
        let mut ix = 0;
        while ix + self.cipher.block_size() <= data.bytes().len() {
            let in_block = &data.bytes()[ix .. ix + self.cipher.block_size()];
            output.extend_from_slice(&self.cipher.encrypt(in_block));
            ix += self.cipher.block_size();
        }

        Data::from_bytes(output)
    }

    /// Decrypts the given data using ECB mode.
    fn ecb_decrypt(&self, data: &Data) -> Data {

        // Somewhere to store the resulting encrypted message.
        let mut output = Vec::with_capacity(data.bytes().len());

        // Iterate over the data, one block at a time, encrypting them, and
        // storing the results.
        let mut ix = 0;
        while ix < data.bytes().len() {
            let in_block = &data.bytes()[ix .. ix + self.cipher.block_size()];
            output.extend_from_slice(&self.cipher.decrypt(in_block));
            ix += self.cipher.block_size();
        }

        Data::from_bytes(output)
    }

    /// Pads the given data using PKCS#7
    fn pkcs7_pad(&self, data: &Data) -> Data {

        // Work out the value of the padding bytes.
        let pad_value = ((data.bytes().len() - 1) % 16) + 1;

        // Construct a new Data with the padding included.
        let mut new_bytes = data.bytes().to_vec().clone();
        for _ in 0..pad_value {
            new_bytes.push(pad_value as u8);
        }
        Data::from_bytes(new_bytes)
    }

    /// Unpads the given data using PKCS#7
    fn pkcs7_unpad(&self, data: &Data) -> Data {

        // Remove the last N bytes, where N is the value of the final byte.
        let pad_value = data.bytes()[data.bytes().len() - 1] as usize;
        let new_bytes = &data.bytes()[..data.bytes().len() - pad_value];
        Data::from_bytes(new_bytes.to_vec())
    }
}