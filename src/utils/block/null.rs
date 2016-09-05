//! Null encryption and decryption - encrypt and decrypt are no-ops.

use utils::block::Cipher;

/// A null encryptor and decryptor.
pub struct NullCipher {
    block_size: usize
}

impl NullCipher {

    /// Create a new NullCipher with the given block size.
    pub fn new(block_size: usize) -> NullCipher {
        NullCipher{block_size: block_size}
    }
}

impl Cipher for NullCipher {

    /// Encrypt a single block of bytes.
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        input.to_vec()
    }

    /// Decrypt a single block of bytes.
    fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        input.to_vec()
    }

    /// Return the block size of this cipher.
    fn block_size(&self) -> usize {
        self.block_size
    }
}