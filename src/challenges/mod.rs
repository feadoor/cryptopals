//! Solutions to the cryptopals challenges themselves, broken down by set.
//!
//! Each challenge returns a `ChallengeResults`. These are the results of a particular challenge,
//! including, when relevant, encrypted/decrypted inputs/outputs, cryptographic keys, outcomes of
//! attacks and other such data. These outputs will be printed to the terminal when the challenge
//! is run as part of the executable, and are also checked against the known answers as unit tests
//! for the challenges.

pub mod set1;
pub mod set2;

use ansi_term::Colour::{Cyan, Green};

use std::fmt;
use std::string::String;

/// The results of running a particular challenge.
pub struct ChallengeResults {
    /// The set that this challenge belongs to.
    pub set: usize,
    /// The challenge number.
    pub challenge: usize,
    /// A description of the challenge.
    pub description: String,
    /// An array holding the outputs from this challenge.
    pub outputs: Vec<(String, String)>,
}

impl ChallengeResults {
    /// Assert that a particular key is present and holds the expected value.
    pub fn check(&self, exp_key: &str, exp_val: &str) {
        for &(ref key, ref value) in &self.outputs {
            if key == exp_key {
                assert!(value == exp_val);
            }
        }

        assert!(false, "The key is not present");
    }
}

impl fmt::Display for ChallengeResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let long_desc = format!("Set {} Challenge {} - {}",
                                self.set,
                                self.challenge,
                                self.description);
        try!(write!(f, "\n{}\n", Green.bold().paint(long_desc)));
        for &(ref key, ref value) in &self.outputs {
            try!(write!(f, "\n{}: {}\n", Cyan.bold().paint(key.to_string()), value));
        }
        Ok(())
    }
}

/// A builder for the `ChallengeResults` struct.
#[derive(Default)]
pub struct ChallengeResultsBuilder {
    /// The set that this challenge belongs to.
    pub set: usize,
    /// The challenge number.
    pub challenge: usize,
    /// A description of the challenge.
    pub description: String,
    /// An array holding the outputs from this challenge.
    pub outputs: Vec<(String, String)>,
}

impl ChallengeResultsBuilder {
    /// Create a new `ChallengeResultsBuilder`.
    pub fn new() -> ChallengeResultsBuilder {
        ChallengeResultsBuilder {
            set: 0,
            challenge: 0,
            description: "".to_string(),
            outputs: Vec::new(),
        }
    }

    /// Change the set number that this challenge belongs to.
    pub fn set(mut self, set: usize) -> ChallengeResultsBuilder {
        self.set = set;
        self
    }

    /// Change the challenge number.
    pub fn challenge(mut self, challenge: usize) -> ChallengeResultsBuilder {
        self.challenge = challenge;
        self
    }

    /// Change the description of thsi challenge.
    pub fn description(mut self, description: &str) -> ChallengeResultsBuilder {
        self.description = description.to_string();
        self
    }

    /// Add a new output to this challenge.
    pub fn output(mut self, key: &str, value: &str) -> ChallengeResultsBuilder {
        self.outputs.push((key.to_string(), value.to_string()));
        self
    }

    /// Create a `ChallengeResults` from this builder.
    pub fn finalize(self) -> ChallengeResults {
        ChallengeResults {
            set: self.set,
            challenge: self.challenge,
            description: self.description,
            outputs: self.outputs,
        }
    }
}