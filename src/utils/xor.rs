//! Functions used for encrypting and decrypting data using XOR.

use utils::data::Data;

/// XORs the given data with a repeating key.
///
/// # Example
///
/// ```
/// let data = Data::from_text("Some text");
/// let key  = Data::from_text("secret");
/// let result = xor(&data, &key);
/// ```
pub fn xor(data: &Data, key: &Data) -> Data {

    // Create a new vector to store the resulting bytes in.
    let mut bytes = Vec::with_capacity(data.bytes().len());

    // Repeatedly loop over the key and XOR the data bytes.
    let mut it = data.bytes().iter();
    'outer: loop {
        for k_byte in key.bytes().iter() {
            let e_byte = match it.next() {
                None => break 'outer,
                Some(d_byte) => *k_byte ^ *d_byte,
            };
            bytes.push(e_byte);
        }
    }

    Data::from_bytes(bytes)
}
