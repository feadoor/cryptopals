//! Black-box implementations of cryptographic algorithms, as
//! described in individual challenges.
//!
//! These black boxes will often be the target of cryptographic attacks.

use rand;
use rand::Rng;

use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;

/// A black box which encrypts some input data using either ECB or CBC against
/// an unknown key, and with some random noise added to both ends of the input.
///
/// # Goal
///
/// To be able to determine which mode has been used.
pub struct EcbOrCbc {
    /// The last mode that was used for encryption.
    last_mode: OperationModes,
}

impl EcbOrCbc {
    /// Create a new EcbOrCbc.
    ///
    /// # Example
    ///
    /// ```
    /// let ecb_cbc_box = EcbOrCbc::new();
    /// ```
    pub fn new() -> EcbOrCbc {
        EcbOrCbc { last_mode: OperationModes::Ecb } // This is a lie - never mind.
    }

    /// Encrypt the input data.
    ///
    /// Choose ECB or CBC mode at random, and generate some random noise to go
    /// on either end of the plaintext before encryption.
    ///
    /// # Example
    ///
    /// ```
    /// let ecb_cbc_box = EcbOrCbc::new();
    /// let data = Data::from_text("Please encrypt this");
    /// let output = ecb_cbc_box.encrypt(&data);
    /// ```
    pub fn encrypt(&mut self, input: &Data) -> Data {

        // Generate a random key.
        let key = Data::random(16);

        // Decide whether to use ECB mode.
        let ecb: bool = rand::random();

        // Generate some random bytes at the start and end of the input.
        let mut noisy_input = Vec::with_capacity(input.bytes().len() + 20);
        let before_count = rand::thread_rng().gen_range(5, 11);
        let after_count = rand::thread_rng().gen_range(5, 11);
        let before_data = Data::random(before_count);
        let after_data = Data::random(after_count);

        noisy_input.extend_from_slice(before_data.bytes());
        noisy_input.extend_from_slice(input.bytes());
        noisy_input.extend_from_slice(after_data.bytes());
        let noisy_data = Data::from_bytes(noisy_input);

        // Create the BlockCipher to perform the encryption. Generate a random
        // IV for CBC mode.
        let block;
        if ecb {
            self.last_mode = OperationModes::Ecb;
            block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &key)
                .unwrap();
        } else {
            let iv = Data::random(16);
            self.last_mode = OperationModes::Cbc(iv.clone());
            block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Cbc(iv),
                                     PaddingSchemes::Pkcs7,
                                     &key)
                .unwrap();
        }

        // Return the encrypted Data.
        block.encrypt(&noisy_data)
    }

    /// Check the given answer concerning whether or not the previous text was
    /// encrypted using ECB mode.
    ///
    /// # Example
    ///
    /// ```
    /// let ecb_cbc_box = EcbOrCbc::new();
    /// let data = Data::from_text("Some text to encrypt");
    /// let output = ecb_cbc_box.encrypt(&data);
    /// let correct = ecb_cbc_box.check_answer(true);
    /// ```
    pub fn check_answer(&self, is_ecb: bool) -> bool {
        match self.last_mode {
            OperationModes::Ecb => is_ecb,
            _ => !is_ecb,
        }
    }
}

/// A black box which encrypts some input data by appending a fixed, unknown
/// suffix, and then encrypts under ECB mode with a fixed, unknown key.
///
/// # Goal
///
/// To be able to determine the suffix.
pub struct EcbWithSuffix {
    /// The BlockCipher used to encrypt data.
    block: BlockCipher,
    /// The fixed suffix which is appended to inputs.
    suffix: Data,
}

impl EcbWithSuffix {
    /// Creates a new EcbWithSuffix which uses the given suffix.
    ///
    /// # Example
    ///
    /// ```
    /// let suffix = Data::from_text("Secret suffix");
    /// let ecb_suffix_box = EcbWithSuffix::new(suffix);
    /// ```
    pub fn new(suffix: Data) -> EcbWithSuffix {
        let key = Data::random(16);
        let block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &key)
            .unwrap();
        EcbWithSuffix {
            block: block,
            suffix: suffix,
        }
    }

    /// Encrypts the input data.
    ///
    /// First appends the suffix to the given data, then encrypts under ECB
    /// mode.
    ///
    /// # Example
    ///
    /// ```
    /// let suffix = Data::from_text("Secret suffix");
    /// let ecb_suffix_box = EcbWithSuffix::new(suffix);
    /// let input = Data::from_text("Please encrypt this text");
    /// let output = ecb_suffix_box.encrypt(&input);
    /// ```
    pub fn encrypt(&self, input: &Data) -> Data {
        let new_input_size = input.bytes().len() + self.suffix.bytes().len();
        let mut new_input_bytes = Vec::with_capacity(new_input_size);
        new_input_bytes.extend_from_slice(&input.bytes());
        new_input_bytes.extend_from_slice(&self.suffix.bytes());
        let new_input = Data::from_bytes(new_input_bytes);

        self.block.encrypt(&new_input)
    }

    /// Checks if the suffix has been correctly determined.
    ///
    /// # Example
    ///
    /// ```
    /// let suffix = Data::from_text("Secret suffix");
    /// let ecb_suffix_box = EcbWithSuffix::new(suffix);
    /// let guess = Data::from_text("Wrong suffix");
    /// let correct = ecb_suffix_box.check_answer(&guess);
    /// ```
    pub fn check_answer(&self, suffix_guess: &Data) -> bool {
        suffix_guess.bytes() == self.suffix.bytes()
    }
}
