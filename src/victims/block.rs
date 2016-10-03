//! Implementations of insecure block-cryptographic algorithms.

use std::collections::HashMap;

use rand;
use rand::Rng;

use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes};
use utils::data::Data;

/// Encrypts data under a random choice of ECB or CBC.
///
/// A black box which encrypts some input data using either ECB or CBC against an unknown key, and
/// with some random noise added to both ends of the input.
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
    pub fn new() -> EcbOrCbc {
        EcbOrCbc { last_mode: OperationModes::Ecb } // This is a lie - never mind.
    }

    /// Encrypt the input data.
    ///
    /// Choose ECB or CBC mode at random, and generate some random noise to go on either end of the
    /// plaintext before encryption.
    pub fn encrypt(&mut self, input: &Data) -> Data {

        // Generate a random key.
        let key = Data::random(16);

        // Decide whether to use ECB mode.
        let ecb: bool = rand::random();

        // Generate some random bytes at the start and end of the input.
        let mut noisy_input = Vec::with_capacity(input.len() + 20);
        let before_count = rand::thread_rng().gen_range(5, 11);
        let after_count = rand::thread_rng().gen_range(5, 11);
        let before_data = Data::random(before_count);
        let after_data = Data::random(after_count);

        noisy_input.extend_from_slice(before_data.bytes());
        noisy_input.extend_from_slice(input.bytes());
        noisy_input.extend_from_slice(after_data.bytes());
        let noisy_data = Data::from_bytes(noisy_input);

        // Create the BlockCipher to perform the encryption. Generate a random IV for CBC mode.
        let block = if ecb {
            self.last_mode = OperationModes::Ecb;
            BlockCipher::new(Algorithms::Aes,
                             OperationModes::Ecb,
                             PaddingSchemes::Pkcs7,
                             &key)
                .unwrap()
        } else {
            let iv = Data::random(16);
            self.last_mode = OperationModes::Cbc(iv.clone());
            BlockCipher::new(Algorithms::Aes,
                             OperationModes::Cbc(iv),
                             PaddingSchemes::Pkcs7,
                             &key)
                .unwrap()
        };

        // Return the encrypted Data.
        block.encrypt(&noisy_data).unwrap()
    }

    /// Check the given answer concerning whether or not the previous text was encrypted using ECB
    /// mode.
    pub fn check_answer(&self, is_ecb: bool) -> bool {
        match self.last_mode {
            OperationModes::Ecb => is_ecb,
            _ => !is_ecb,
        }
    }
}

impl Default for EcbOrCbc {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypts data under ECB after adding a suffix.
///
/// A black box which encrypts some input data by appending a fixed, unknown suffix, and then
/// encrypts under ECB mode with a fixed, unknown key.
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
    /// First appends the suffix to the given data, then encrypts under ECB mode.
    pub fn encrypt(&self, input: &Data) -> Data {
        let new_input_size = input.len() + self.suffix.len();
        let mut new_input_bytes = Vec::with_capacity(new_input_size);
        new_input_bytes.extend_from_slice(input.bytes());
        new_input_bytes.extend_from_slice(self.suffix.bytes());
        let new_input = Data::from_bytes(new_input_bytes);

        self.block.encrypt(&new_input).unwrap()
    }

    /// Checks if the suffix has been correctly determined.
    pub fn check_answer(&self, suffix_guess: &Data) -> bool {
        suffix_guess.bytes() == self.suffix.bytes()
    }
}


/// Creates ECB-encrypted user tokens.
///
/// A black box which takes an email address, sanitises the input, creates a token of the form
/// `email=<user_email>&uid=10&role=user`, then encrypts that under ECB using a block size of 16
/// bytes, and returns the result.
///
/// # Goal
///
/// To obtain (by any means) a token which decrypts to one containing "role=admin".
pub struct EcbUserProfile {
    /// The BlockCipher that this black box uses to encrypt data.
    block: BlockCipher,
}

impl EcbUserProfile {
    /// Creates a new EcbUserProfile.
    pub fn new() -> EcbUserProfile {
        let key = Data::random(16);
        let block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &key)
            .unwrap();
        EcbUserProfile { block: block }
    }

    /// Create a token for the given email address.
    pub fn make_token(&self, email: &str) -> Data {
        // First remove any metacharacters from the given email address.
        let sanitised = email.replace("&", "").replace("=", "");

        // Now form the token and return it in encrypted form.
        let mut plain = "email=".to_string();
        plain.push_str(&sanitised);
        plain.push_str("&uid=10&role=user");
        let token = Data::from_text(&plain);
        self.block.encrypt(&token).unwrap()
    }

    /// Decrypt and parse a token.
    fn read_token(&self, token: &Data) -> Result<HashMap<String, String>, &str> {
        // First decrypt the encrypted token.
        let plain = self.block.decrypt(token).unwrap().to_text();

        // Now split on occurrences of '&' and read the 'k=v' pairs.
        let mut pairs = HashMap::new();
        for pair in plain.split('&') {
            let mut keyval = pair.split('=');
            let key = match keyval.next() {
                Some(x) => x,
                None => return Err("Invalid key-value pair: no key"),
            };
            let val = match keyval.next() {
                Some(x) => x,
                None => return Err("Invalid key-value pair: no value"),
            };
            if let Some(_) = keyval.next() {
                return Err("Invalid key-value pair: too many items");
            }
            pairs.insert(key.to_string(), val.to_string());
        }

        Ok(pairs)
    }

    /// Parses an encrypted token, and returns `true` or `false` according to whether the token
    /// represents a profile containing `role=admin`.
    pub fn is_admin(&self, token: &Data) -> bool {
        // Decrypt and read the token.
        let pairs = match self.read_token(token) {
            Ok(x) => x,
            Err(_) => return false,
        };

        if pairs.get(&"role".to_string()) == Some(&"admin".to_string()) {
            return true;
        }

        false
    }
}

impl Default for EcbUserProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypts data under ECB after adding a prefix and a suffix.
///
/// A black box which encrypts some input data by appending a fixed, unknown preifx and suffix,
/// and then encrypts under ECB mode with a fixed, unknown key.
///
/// # Goal
///
/// To be able to determine the suffix.
pub struct EcbWithAffixes {
    /// The BlockCipher used to encrypt data.
    block: BlockCipher,
    /// The fixed prefix which is appended to inputs.
    prefix: Data,
    /// The fixed suffix which is appended to inputs.
    suffix: Data,
}

impl EcbWithAffixes {
    /// Creates a new EcbWithAffixes which uses the given suffix and a random prefix.
    pub fn new(suffix: Data) -> EcbWithAffixes {
        let key = Data::random(16);
        let prefix_len = rand::thread_rng().gen_range(5, 25);
        let prefix = Data::random(prefix_len);
        let block = BlockCipher::new(Algorithms::Aes,
                                     OperationModes::Ecb,
                                     PaddingSchemes::Pkcs7,
                                     &key)
            .unwrap();
        EcbWithAffixes {
            block: block,
            prefix: prefix,
            suffix: suffix,
        }
    }

    /// Encrypts the input data.
    ///
    /// First appends the prefix and suffix to the given data, then encrypts under ECB mode.
    pub fn encrypt(&self, input: &Data) -> Data {
        let new_input_size = input.len() + self.prefix.len() + self.suffix.len();
        let mut new_input_bytes = Vec::with_capacity(new_input_size);
        new_input_bytes.extend_from_slice(self.prefix.bytes());
        new_input_bytes.extend_from_slice(input.bytes());
        new_input_bytes.extend_from_slice(self.suffix.bytes());
        let new_input = Data::from_bytes(new_input_bytes);

        self.block.encrypt(&new_input).unwrap()
    }

    /// Checks if the suffix has been correctly determined.
    pub fn check_answer(&self, suffix_guess: &Data) -> bool {
        suffix_guess.bytes() == self.suffix.bytes()
    }
}
