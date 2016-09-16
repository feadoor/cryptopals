//! Implementations of cryptographic attacks against block ciphers.

use blackboxes::{EcbWithSuffix, EcbWithAffixes};
use utils::data::Data;

/// Decrypt an unknown suffix encrypted under ECB mode.
///
/// Given a black box which adds an unknown suffix to input data before encrypting under ECB mode
/// with the given block size, determine the suffix.
pub fn find_ecb_suffix(ecb_suffix_box: &EcbWithSuffix, block_size: usize) -> Data {

    // Keep track of the suffix bytes that we have decrypted so far.
    let mut suffix = Vec::new();

    // Decrypt the suffix one byte at a time.
    'outer: loop {

        // Pad the known suffix with null bytes until it finishes one byte before a block boundary.
        let num_bytes = block_size - 1 - (suffix.len() % block_size);
        let padding = vec![0; num_bytes];
        let mut padded_known = padding.clone();
        padded_known.extend_from_slice(&suffix);

        // Pass the padding into the box, and grab the encrypted block which corresponds to our
        // input block whose last byte we are trying to determine.
        let block_pos = padding.len() + suffix.len() + 1 - block_size;
        let output = ecb_suffix_box.encrypt(&Data::from_bytes(padding));
        if output.len() <= block_pos + block_size {
            // We've retrieved the whole suffix, so break.
            break;
        }
        let block = &output.bytes()[block_pos..block_pos + block_size];

        // Compare the encrypted block against all the possible outputs that the block could
        // encrypt to, depending on its final byte.
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

/// Find the length of an unknown prefix which is appended to ECB-encrypted messages.
fn find_ecb_prefix_len(ecb_affixes_box: &EcbWithAffixes, block_size: usize) -> usize {

    // Find the block in which the prefix ends, by finding the first block which is different upon
    // inserting a null byte.
    let empty = ecb_affixes_box.encrypt(&Data::new());
    let noisy = ecb_affixes_box.encrypt(&Data::from_bytes(vec![0]));

    let mut prefix_block = 0;
    for (ix, (byte1, byte2)) in empty.bytes().iter().zip(noisy.bytes().iter()).enumerate() {
        if byte1 != byte2 {
            prefix_block = ix / block_size;
            break;
        }
    }

    // Now find the length of the prefix modulo the block size, by finding the smallest number of
    // null bytes we need to provide as input in order to produce repeated blocks.
    let mut prefix_len = block_size * prefix_block;
    for ix in 0..block_size {
        let repeats = Data::from_bytes(vec![0; 2 * block_size + ix]);
        let output = ecb_affixes_box.encrypt(&repeats);
        if output.bytes()[block_size * (prefix_block + 1)..block_size * (prefix_block + 2)] ==
           output.bytes()[block_size * (prefix_block + 2)..block_size * (prefix_block + 3)] {
            prefix_len += block_size - ix;
            break;
        }
    }

    prefix_len
}

/// Decrypt an unknown suffix encrypted under ECB mode, when a prefix is also added.
///
/// Given a black box which adds an unknown prefix and suffix to input data before encrypting under
/// ECB mode with the given block size, determine the suffix.
pub fn find_ecb_suffix_with_prefix(ecb_affixes_box: &EcbWithAffixes, block_size: usize) -> Data {

    // First, find the length of the prefix, which is currently unknown.
    let prefix_len = find_ecb_prefix_len(ecb_affixes_box, block_size);

    // Keep track of the suffix bytes that we have decrypted so far.
    let mut suffix = Vec::new();

    // Decrypt the suffix one byte at a time.
    'outer: loop {

        // Pad the known suffix with null bytes until it finishes one byte before a block boundary.
        let num_bytes = 2 * block_size - 1 - ((prefix_len + suffix.len()) % block_size);
        let padding = vec![0; num_bytes];
        let mut padded_known = vec![0; prefix_len];
        padded_known.extend_from_slice(&padding);
        padded_known.extend_from_slice(&suffix);

        // Pass the padding into the box, and grab the encrypted block which corresponds to our
        // input block whose last byte we are trying to determine.
        let block_pos = prefix_len + padding.len() + suffix.len() + 1 - block_size;
        let output = ecb_affixes_box.encrypt(&Data::from_bytes(padding));
        if output.len() <= block_pos + block_size {
            // We've retrieved the whole suffix, so break.
            break;
        }
        let block = &output.bytes()[block_pos..block_pos + block_size];

        // Compare the encrypted block against all the possible outputs that the block could
        // encrypt to, depending on its final byte.
        let partial_block = &padded_known[block_pos..];
        let extra_padding = block_size - (prefix_len % block_size);
        let output_start = prefix_len + extra_padding;

        for byte in 0..256 {
            let mut test_block = vec![0; block_size - (prefix_len % block_size)];
            test_block.extend_from_slice(partial_block);
            test_block.push(byte as u8);
            let output = ecb_affixes_box.encrypt(&Data::from_bytes(test_block));
            if &output.bytes()[output_start..output_start + block_size] == block {
                suffix.push(byte as u8);
                continue 'outer;
            }
        }
    }

    Data::from_bytes(suffix)
}