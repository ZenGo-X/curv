/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/
pub mod elliptic;

pub mod arithmetic;
pub use crate::arithmetic::BigInt;
use std::{error, fmt};

pub mod cryptographic_primitives;

mod marker;
pub use marker::HashChoice;

mod test_utils;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

impl fmt::Display for ErrorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKey::InvalidPublicKey => f.write_str("Invalid Public Key"),
        }
    }
}
impl error::Error for ErrorKey {}

#[derive(Debug)]
pub enum ErrorSS {
    VerifyShareError,
}

impl fmt::Display for ErrorSS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSS::VerifyShareError => f.write_str("Failed verifying the Secret Share"),
        }
    }
}
impl error::Error for ErrorSS {}
