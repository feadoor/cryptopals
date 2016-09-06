//! Solutions to the Cryptopals crypto challenges.
//!
//! https://cryptopals.com/

extern crate rand;

pub mod attacks;
pub mod blackboxes;
pub mod utils;
pub mod set1;
pub mod set2;

fn main() {

    // Run the challenges in Set 1.
    set1::challenge01();
    set1::challenge02();
    set1::challenge03();
    set1::challenge04();
    set1::challenge05();
    set1::challenge06();
    set1::challenge07();
    set1::challenge08();

    // Run the challenges in Set 2.
    set2::challenge09();
    set2::challenge10();
    set2::challenge11();
    set2::challenge12();
}