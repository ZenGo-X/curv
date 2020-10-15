/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/
#[macro_use]
extern crate serde_derive;

//#[cfg(feature = "ecc")]
pub mod elliptic;

#[cfg(feature = "ec_ristretto")]
mod curveristrettoinstance {
    pub use crate::elliptic::curves::curve_ristretto::FE;
    pub use crate::elliptic::curves::curve_ristretto::GE;
    pub use crate::elliptic::curves::curve_ristretto::PK;
    pub use crate::elliptic::curves::curve_ristretto::SK;
}

#[cfg(feature = "ec_ristretto")]
pub use self::curveristrettoinstance::*;


#[cfg(feature = "ec_secp256k1")]
mod secp256k1instance {
    pub use crate::elliptic::curves::secp256_k1::FE;
    pub use crate::elliptic::curves::secp256_k1::GE;
    pub use crate::elliptic::curves::secp256_k1::PK;
    pub use crate::elliptic::curves::secp256_k1::SK;
}

#[cfg(feature = "ec_secp256k1")]
pub use self::secp256k1instance::*;


#[cfg(feature = "ec_ed25519")]
mod ed25519instance {
    pub use crate::elliptic::curves::ed25519::FE;
    pub use crate::elliptic::curves::ed25519::GE;
    pub use crate::elliptic::curves::ed25519::PK;
    pub use crate::elliptic::curves::ed25519::SK;
}

#[cfg(feature = "ec_ed25519")]
pub use self::ed25519instance::*;

#[cfg(feature = "ec_jubjub")]
mod jubjubinstance {
    pub use crate::elliptic::curves::curve_jubjub::FE;
    pub use crate::elliptic::curves::curve_jubjub::GE;
    pub use crate::elliptic::curves::curve_jubjub::PK;
    pub use crate::elliptic::curves::curve_jubjub::SK;
}

#[cfg(feature = "ec_jubjub")]
pub use self::jubjubinstance::*;

#[cfg(any(feature = "ec_g1",feature = "ec_bls12_381"))]
mod bls12_381_instance {
    pub use crate::elliptic::curves::bls12_381::g1::FE;
    pub use crate::elliptic::curves::bls12_381::g1::GE;
    pub use crate::elliptic::curves::bls12_381::g1::PK;
    pub use crate::elliptic::curves::bls12_381::g1::SK;
}


#[cfg(any(feature = "ec_g1",feature = "ec_bls12_381"))]
pub use self::bls12_381_instance::*;

#[cfg(feature = "ec_p256")]
mod p256instance {
    pub use crate::elliptic::curves::p256::FE;
    pub use crate::elliptic::curves::p256::GE;
    pub use crate::elliptic::curves::p256::PK;
    pub use crate::elliptic::curves::p256::SK;
}

#[cfg(feature = "ec_p256")]
pub use self::p256instance::*;



#[cfg(feature = "ec_g2")]
mod g2_instance {
    pub use crate::elliptic::curves::bls12_381::g2::FE;
    pub use crate::elliptic::curves::bls12_381::g2::GE;
    pub use crate::elliptic::curves::bls12_381::g2::PK;
    pub use crate::elliptic::curves::bls12_381::g2::SK;
}

#[cfg(feature = "ec_g2")]
pub use self::g2_instance::*;



#[cfg(feature = "rust-gmp")]
pub mod arithmetic;

#[cfg(feature = "rust-gmp")]
pub use crate::arithmetic::big_gmp::BigInt;

#[cfg(feature = "ecc")]
pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}
