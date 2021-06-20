/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

#![allow(clippy::upper_case_acronyms)]

pub mod elliptic;

pub mod arithmetic;
pub use crate::arithmetic::BigInt;
use std::{error, fmt};

pub mod cryptographic_primitives;

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

#[cfg(test)]
#[macro_export]
macro_rules! test_for_all_curves {
    (#[should_panic] $fn: ident) => {
        crate::test_for_all_curves!([#[should_panic]] $fn);
    };
    ($fn: ident) => {
        crate::test_for_all_curves!([] $fn);
    };
    ([$($attrs:tt)*] $fn: ident) => {
        paste::paste!{
            #[test]
            $($attrs)*
            fn [<$fn _secp256k1>]() {
                $fn::<crate::elliptic::curves::secp256_k1::GE>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _ristretto>]() {
                $fn::<crate::elliptic::curves::curve_ristretto::GE>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _ed25519>]() {
                $fn::<crate::elliptic::curves::ed25519::GE>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _bls12_381>]() {
                $fn::<crate::elliptic::curves::bls12_381::g1::GE>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _p256>]() {
                $fn::<crate::elliptic::curves::p256::GE>()
            }
        }
    };
}
