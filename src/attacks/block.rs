//! Implementations of cryptographic attacks against block ciphers.

use blackboxes::EcbWithSuffix;
use utils::data::Data;

/// Decrypt an unknown suffix encrypted under ECB mode.
///
/// Given a black box which adds an unknown suffix to input data before
/// encrypting under ECB mode with the given block size, determine the suffix.
pub fn find_ecb_suffix(ecb_suffix_box: &EcbWithSuffix, block_size: usize) -> Data {

    // Keep track of the suffix bytes that we have decrypted so far.
    let mut suffix = Vec::new();

    // Decrypt the suffix one byte at a time.
    'outer: loop {

        // Pad the known suffix with null bytes until it finishes one byte
        // before a block boundary.
        let num_bytes = block_size - 1 - (suffix.len() % block_size);
        let padding = vec![0; num_bytes];
        let mut padded_known = padding.clone();
        padded_known.extend_from_slice(&suffix);

        // Pass the padding into the box, and grab the encrypted block
        // which corresponds to our input block whose last byte we are trying
        // to determine.
        let block_pos = padding.len() + suffix.len() + 1 - block_size;
        let output = ecb_suffix_box.encrypt(&Data::from_bytes(padding));
        if output.bytes().len() <= block_pos + block_size {
            // We've retrieved the whole suffix, so break.
            break;
        }
        let block = &output.bytes()[block_pos..block_pos + block_size];

        // Compare the encrypted block against all the possible outputs that
        // the block could encrypt to, depending on its final byte.
        let partial_block = &padded_known[block_pos..];

        for byte in 0..256 {
            let mut test_block = partial_block.to_vec();
            test_block.push(byte as u8);
            let output = ecb_suffix_box.encrypt(&Data::from_bytes(test_block));
            if &output.bytes()[..block_size] == block {
                suffix.push(byte as u8);
                continue 'outer;
            }
        }
    }

    Data::from_bytes(suffix)
}
