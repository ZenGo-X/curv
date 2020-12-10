/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

#[macro_use]
extern crate serde_derive;

pub mod elliptic;

pub mod arithmetic;
pub use crate::arithmetic::big_gmp::BigInt;

pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

/// Helps write tests generic over choice of elliptic curve
///
/// As input it expects name of a function which takes one generic parameter:
/// curve implementation. Function restricted to have no arguments and return `()`.
/// Macro outputs several tests each one runs given function with specific curve implementation.
///
/// ## Example
/// Suppose you have following generic test:
/// ```rust
/// # use curv::elliptic::curves::traits::*;
/// # use curv::test_for_all_curves;
/// test_for_all_curves!(test_dh);
/// fn test_dh<P: ECPoint>()
/// where P: ECPoint + Clone,
///       P::Scalar: Clone,
/// {
///     let party_a_secret: P::Scalar = ECScalar::new_random();
///     let party_a_public = P::generator() * party_a_secret.clone();
///
///     let party_b_secret: P::Scalar = ECScalar::new_random();
///     let party_b_public = P::generator() * party_b_secret.clone();
///
///     let party_a_share = party_b_public * party_a_secret;
///     let party_b_share = party_a_public * party_b_secret;
///
///     assert!(party_a_share == party_b_share, "Parties share expected to be the same")
/// }
/// # test_dh::<curv::elliptic::curves::secp256_k1::GE>();
/// ```
///
/// Macro will generate this code for you:
/// ```rust
/// # use curv::elliptic::curves::traits::*;
/// # fn test_dh<P: ECPoint>() { /* see code snippet above */ }
/// #[test]
/// fn test_dh_secp256k1() {
///     test_dh::<curv::elliptic::curves::secp256_k1::GE>()
/// }
/// #[test]
/// fn test_dh_ristretto() {
///     test_dh::<curv::elliptic::curves::curve_ristretto::GE>()
/// }
/// #[test]
/// fn test_dh_ed25519() {
///     test_dh::<curv::elliptic::curves::ed25519::GE>()
/// }
/// #[test]
/// fn test_dh_bls12_381() {
///     test_dh::<curv::elliptic::curves::bls12_381::GE>()
/// }
/// #[test]
/// fn test_dh_p256() {
///     test_dh::<curv::elliptic::curves::p256::GE>()
/// }
/// ```
///
/// ## Attributes
/// You can also pass `#[should_panic]` attribute:
/// ```rust
/// # use curv::elliptic::curves::traits::*;
/// # use curv::test_for_all_curves;
/// test_for_all_curves!(#[should_panic] failure_test);
/// fn failure_test<P: ECPoint>() { /* ... */  }
/// ```
///
/// This will require every produced test to panic.
#[cfg(any(test, feature = "testing-utils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing-utils")))]
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
                $fn::<crate::elliptic::curves::bls12_381::GE>()
            }
            #[test]
            $($attrs)*
            fn [<$fn _p256>]() {
                $fn::<crate::elliptic::curves::p256::GE>()
            }
        }
    };
}
