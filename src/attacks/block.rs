//! Implementations of cryptographic attacks against block ciphers.

use blackboxes::{EcbOrCbc, EcbWithSuffix, EcbWithAffixes, EcbUserProfile};
use utils::data::Data;
use utils::metrics;

/// Determine whether a block cipher is using ECB or CBC mode.
///
/// Given a black box which encrypts (padded) user data under ECB mode or CBC mode at random,
/// detect which mode it is using.
pub fn is_ecb_mode(ecb_cbc_box: &mut EcbOrCbc) -> bool {

    // Find a lower bound on the block size of the cipher by encrypting some empty data.
    let block_size = ecb_cbc_box.encrypt(&Data::new()).len();

    // Provide some input data which will definitely result in repeated blocks under ECB mode.
    let input = Data::from_bytes(vec![0; 10 * block_size]);
    let encrypted = ecb_cbc_box.encrypt(&input);
    metrics::has_repeated_blocks(&encrypted, block_size)
}

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

/// Create a token which the EcbUserProfile decodes into a user profile with admin privileges.
///
/// Given - a black box which, given an email address, creates a user profile encoded in the form
/// `email=<user-email>&uid=10&role=user`, then encrypts that under ECB mode and provides the
/// output as a token to the user.
///
/// This utilises an ECB cut-and-paste attack to create an admin token.
pub fn craft_ecb_admin_token(ecb_profile_box: &EcbUserProfile) -> Data {

    // Paste together non-admin tokens in order to create an admin token. This works by first
    // asking for the following three tokens:
    //
    //                           0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    // email@foo.com         --> email=email@foo. com&uid=10&role= user
    // noone@fakeadmin       --> email=noone@fake admin&uid=10&rol e=user
    // useless@madeup.com    --> email=useless@ma deup.com&uid=10& role=user
    //
    // If we then take the first two blocks of the first token, the second block of the second
    // token and the final block of the third token, and paste them together, we will end up with
    // the following token:
    //
    // email=email@foo.com&uid=10&role=admin&uid=10&rolrole=user
    println!("Crafting admin token...");
    let token1 = ecb_profile_box.make_token("email@foo.com");
    let token2 = ecb_profile_box.make_token("noone@fakeadmin");
    let token3 = ecb_profile_box.make_token("useless@madeup");

    let mut new_token_bytes = Vec::with_capacity(4 * 16);
    new_token_bytes.extend_from_slice(&token1.bytes()[..32]);
    new_token_bytes.extend_from_slice(&token2.bytes()[16..32]);
    new_token_bytes.extend_from_slice(&token3.bytes()[32..]);

    Data::from_bytes(new_token_bytes)
}