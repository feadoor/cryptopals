//! Solutions to the Cryptopals crypto challenges.
//!
//! https://cryptopals.com/

extern crate ansi_term;
extern crate rand;

pub mod attacks;
pub mod challenges;
pub mod utils;
pub mod victims;

fn main() {

    // Run the challenges in Set 1.
    println!("{}", challenges::set1::challenge01());
    println!("{}", challenges::set1::challenge02());
    println!("{}", challenges::set1::challenge03());
    println!("{}", challenges::set1::challenge04());
    println!("{}", challenges::set1::challenge05());
    println!("{}", challenges::set1::challenge06());
    println!("{}", challenges::set1::challenge07());
    println!("{}", challenges::set1::challenge08());

    // Run the challenges in Set 2.
    //challenges::set2::challenge09();
    //challenges::set2::challenge10();
    //challenges::set2::challenge11();
    //challenges::set2::challenge12();
    //challenges::set2::challenge13();
    //challenges::set2::challenge14();
    //challenges::set2::challenge15();
}
