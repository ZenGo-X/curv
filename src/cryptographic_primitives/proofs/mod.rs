/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
        (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

use std::error::Error;
use std::fmt;

pub mod dlog_zk_protocol;
pub mod sigma_correct_homomorphic_elgamal_encryption_of_dlog;
pub mod sigma_correct_homomrphic_elgamal_enc;
pub mod sigma_dlog;
pub mod sigma_valid_pedersen;
pub mod sigma_valid_pedersen_blind;

#[derive(Debug, Clone, Copy)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}
