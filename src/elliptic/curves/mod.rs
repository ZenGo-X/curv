// pub mod bls12_381;
// pub mod curve_ristretto;
// pub mod ed25519;
// pub mod p256;
pub mod secp256_k1;

mod traits;
mod wrappers;

pub use self::secp256_k1::Secp256k1;
pub use self::{
    traits::{Curve, ECPoint, ECScalar},
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
