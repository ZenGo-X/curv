pub mod bls12_381;
pub mod curve_ristretto;
pub mod ed25519;
pub mod p256;
pub mod secp256_k1;

#[cfg(test)]
mod test;
mod traits;
mod wrappers;

pub use self::{
    bls12_381::{Bls12_381_1, Bls12_381_2},
    curve_ristretto::Ristretto,
    ed25519::Ed25519,
    p256::Secp256r1,
    secp256_k1::Secp256k1,
};
pub use self::{
    traits::{Curve, ECPoint, ECScalar, PointCoords},
    wrappers::{Generator, Point, PointRef, PointZ, Scalar, ScalarZ},
};

pub mod error {
    pub use super::{
        traits::{DeserializationError, NotOnCurve},
        wrappers::error::*,
    };
}

#[doc(no_inline)]
pub use self::error::*;
