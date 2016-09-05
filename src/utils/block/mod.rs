//! Block cipher encryption and decryption using various modes of operation.

mod aes;

use utils::data::Data;

/// Ciphers that can be used for the encryption and decryption of a single
/// block.
pub enum Ciphers {
    /// The AES algorithm.
    Aes
}

/// Block cipher modes of operation.
pub enum OperationModes {
    /// Electronic cookbook (ECB) mode.
    Ecb
}

/// Trait for encrypting and decrypting a single block of bytes, to be used as
/// the core of a block cipher.
pub trait Cipher {
    /// Encrypt a single block of bytes.
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
    /// Decrypt a single block of bytes.
    fn decrypt(&self, input: &[u8]) -> Vec<u8>;
    /// Return the block size used by this cipher.
    fn block_size() -> u32;
}