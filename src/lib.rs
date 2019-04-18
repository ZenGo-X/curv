/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

#[macro_use]
extern crate serde_derive;
extern crate blake2_rfc;
extern crate merkle;
extern crate ring;
extern crate serde;
extern crate serde_json;
extern crate sha3;
extern crate zeroize;

#[cfg(feature = "ecc")]
pub mod elliptic;

#[cfg(feature = "curvesecp256k1")]
mod secp256k1instance {
    pub use elliptic::curves::secp256_k1::FE;
    pub use elliptic::curves::secp256_k1::GE;
    pub use elliptic::curves::secp256_k1::PK;
    pub use elliptic::curves::secp256_k1::SK;
}

#[cfg(feature = "curvesecp256k1")]
pub use self::secp256k1instance::*;

#[cfg(feature = "curveristretto")]
mod curveristrettoinstance {
    pub use elliptic::curves::curve_ristretto::FE;
    pub use elliptic::curves::curve_ristretto::GE;
    pub use elliptic::curves::curve_ristretto::PK;
    pub use elliptic::curves::curve_ristretto::SK;
}

#[cfg(feature = "curveristretto")]
pub use self::curveristrettoinstance::*;

#[cfg(feature = "ed25519")]
mod ed25519instance {
    pub use elliptic::curves::ed25519::FE;
    pub use elliptic::curves::ed25519::GE;
    pub use elliptic::curves::ed25519::PK;
    pub use elliptic::curves::ed25519::SK;
}

#[cfg(feature = "ed25519")]
pub use self::ed25519instance::*;

#[cfg(feature = "curvejubjub")]
mod jubjubinstance {
    pub use elliptic::curves::curve_jubjub::FE;
    pub use elliptic::curves::curve_jubjub::GE;
    pub use elliptic::curves::curve_jubjub::PK;
    pub use elliptic::curves::curve_jubjub::SK;
}

#[cfg(feature = "curvejubjub")]
pub use self::jubjubinstance::*;

pub mod arithmetic;
#[cfg(feature = "gmp")]
pub use arithmetic::big_gmp::BigInt;

#[cfg(feature = "ecc")]
pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}
