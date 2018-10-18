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
#[macro_use]
extern crate serde_derive;
extern crate merkle;
extern crate ring;
extern crate serde;
extern crate serde_json;
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

#[cfg(feature = "curve25519")]
mod curve25519instance {
    pub use elliptic::curves::curve25519::FE;
    pub use elliptic::curves::curve25519::GE;
    pub use elliptic::curves::curve25519::PK;
    pub use elliptic::curves::curve25519::SK;
}

#[cfg(feature = "curve25519")]
pub use self::curve25519instance::*;

// TODO: When we will have more than one type of big num library, add as features
pub mod arithmetic;
pub use arithmetic::big_gmp::BigInt;

pub mod cryptographic_primitives;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}
