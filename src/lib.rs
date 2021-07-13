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

pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

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
                $fn::<crate::elliptic::curves::Secp256k1>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _p256>]() {
                $fn::<crate::elliptic::curves::Secp256r1>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _ed25519>]() {
                $fn::<crate::elliptic::curves::Ed25519>()
            }
            // #[test]
            // $($attrs)*
            // fn [<$fn _ristretto>]() {
            //     $fn::<crate::elliptic::curves::curve_ristretto::GE>()
            // }
            // #[test]
            // $($attrs)*
            // fn [<$fn _bls12_381>]() {
            //     $fn::<crate::elliptic::curves::bls12_381::g1::GE>()
            // }
        }
    };
}
