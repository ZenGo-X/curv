/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

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
