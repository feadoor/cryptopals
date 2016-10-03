//! Helper functions which are useful in solving the challenges but too large to sensibly be
//! inline in the solution itself.

use utils::block::{BlockCipher, Algorithms, OperationModes, PaddingSchemes, DecryptError};
use utils::data::Data;

/// Pad the given `Data` to the given block size using PKCS#7
pub fn pkcs7_pad(data: &Data, block_size: usize) -> Data {
    let block = BlockCipher::new(Algorithms::Null(block_size),
                                 OperationModes::Ecb,
                                 PaddingSchemes::Pkcs7,
                                 &Data::new())
        .unwrap();
    block.encrypt(data).unwrap()
}

/// Unpad the given `Data` using PKCS#7
pub fn pkcs7_unpad(data: &Data) -> Result<Data, DecryptError> {
    let block = BlockCipher::new(Algorithms::Null(1),
                                 OperationModes::Ecb,
                                 PaddingSchemes::Pkcs7,
                                 &Data::new())
        .unwrap();
    block.decrypt(data)
}

/// Add the given padding to some text and return the result as a `Data`
pub fn add_padding(text: &str, padding: &[u8]) -> Data {
    let mut data_bytes = text.as_bytes().to_vec();
    data_bytes.extend_from_slice(padding);
    Data::from_bytes(data_bytes)
}

// Determines if the given data has valid PKSC#7 padding.
pub fn valid_pkcs7(data: &Data) -> bool {
    match pkcs7_unpad(data) {
        Err(DecryptError::Padding) => false,
        _ => true,
    }
}