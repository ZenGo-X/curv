#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::convert::TryInto;
use std::ptr;
use std::sync::atomic;

use curve25519_dalek::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::{Identity, IsIdentity};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::*;
use crate::elliptic::curves::traits::*;

use super::traits::{ECPoint, ECScalar};

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = RistrettoScalar {
        purpose: "intermediate GROUP_ORDER",
        fe: BASEPOINT_ORDER.into(),
    }.to_bigint();

    static ref GENERATOR: RistrettoPoint = RistrettoPoint {
        purpose: "generator",
        ge: RISTRETTO_BASEPOINT_POINT,
    };

    static ref BASE_POINT2: RistrettoPoint = {
        let g = RistrettoPoint::generator();
        let hash = Sha256::digest(&g.serialize(true));
        RistrettoPoint {
            purpose: "base_point2",
            ge: RistrettoPoint::deserialize(&hash).unwrap().ge,
        }
    };
}

pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;

pub type SK = curve25519_dalek::scalar::Scalar;
pub type PK = curve25519_dalek::ristretto::RistrettoPoint;

#[derive(Debug, PartialEq, Clone)]
pub enum Ristretto {}
#[derive(Clone, Debug)]
pub struct RistrettoScalar {
    purpose: &'static str,
    fe: Zeroizing<SK>,
}
#[derive(Clone, Debug, Copy)]
pub struct RistrettoPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = RistrettoPoint;
pub type FE = RistrettoScalar;

impl Curve for Ristretto {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "ristretto";
}

impl ECScalar for RistrettoScalar {
    type Underlying = SK;

    fn random() -> RistrettoScalar {
        RistrettoScalar {
            purpose: "random",
            fe: SK::random(&mut thread_rng()).into(),
        }
    }

    fn zero() -> RistrettoScalar {
        RistrettoScalar {
            purpose: "zero",
            fe: SK::zero().into(),
        }
    }

    fn from_bigint(n: &BigInt) -> RistrettoScalar {
        let curve_order = RistrettoScalar::group_order();
        let mut bytes = n
            .modulus(&curve_order)
            .to_bytes_array::<32>()
            .expect("n mod curve_order must be equal or less than 32 bytes");
        bytes.reverse();
        RistrettoScalar {
            purpose: "from_bigint",
            fe: SK::from_bytes_mod_order(bytes).into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        let mut t = self.fe.to_bytes();
        t.reverse();
        BigInt::from_bytes(&t)
    }

    fn add(&self, other: &Self) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "add",
            fe: (*self.fe + *other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "mul",
            fe: (*self.fe * *other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "sub",
            fe: (*self.fe - *other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        RistrettoScalar {
            purpose: "neg",
            fe: (-&*self.fe).into(),
        }
    }

    fn invert(&self) -> Option<RistrettoScalar> {
        if self.is_zero() {
            None
        } else {
            Some(RistrettoScalar {
                purpose: "invert",
                fe: self.fe.invert().into(),
            })
        }
    }

    fn add_assign(&mut self, other: &Self) {
        *self.fe += &*other.fe;
    }
    fn mul_assign(&mut self, other: &Self) {
        *self.fe *= &*other.fe;
    }
    fn sub_assign(&mut self, other: &Self) {
        *self.fe -= &*other.fe;
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }
    fn from_underlying(fe: Self::Underlying) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl PartialEq for RistrettoScalar {
    fn eq(&self, other: &RistrettoScalar) -> bool {
        self.fe == other.fe
    }
}

impl ECPoint for RistrettoPoint {
    type Scalar = RistrettoScalar;
    type Underlying = PK;

    fn zero() -> RistrettoPoint {
        RistrettoPoint {
            purpose: "zero",
            ge: PK::identity(),
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_identity()
    }

    fn generator() -> &'static RistrettoPoint {
        &GENERATOR
    }

    fn base_point2() -> &'static RistrettoPoint {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<RistrettoPoint, NotOnCurve> {
        let mut y_bytes = y.to_bytes_array::<32>().ok_or(NotOnCurve)?;
        if x != &BigInt::from_bytes(&Sha256::digest(&y_bytes)) {
            return Err(NotOnCurve);
        }

        y_bytes.reverse();
        let compressed = CompressedRistretto::from_slice(&y_bytes);

        Ok(RistrettoPoint {
            purpose: "from_coords",
            ge: compressed.decompress().ok_or(NotOnCurve)?,
        })
    }

    fn x_coord(&self) -> Option<BigInt> {
        // Underlying library intentionally hides x coordinate. We return x=hash(y) as was proposed
        // here: https://github.com/dalek-cryptography/curve25519-dalek/issues/235
        let y = self
            .y_coord()?
            .to_bytes_array::<32>()
            .expect("y coordinate is mod n, meaning it must be <= 32 bytes");
        let x = Sha256::digest(&y);
        Some(BigInt::from_bytes(&x))
    }

    fn y_coord(&self) -> Option<BigInt> {
        let mut y = self.ge.compress().to_bytes();
        y.reverse();
        Some(BigInt::from_bytes(&y[..]))
    }

    fn coords(&self) -> Option<PointCoords> {
        let y = self.y_coord()?;
        let y_bytes = y
            .to_bytes_array::<32>()
            .expect("y coordinate is mod n, meaning it must be <= 32 bytes");
        let x = Sha256::digest(&y_bytes);
        Some(PointCoords {
            x: BigInt::from_bytes(&x),
            y,
        })
    }

    fn serialize(&self, _compressed: bool) -> Vec<u8> {
        self.ge.compress().to_bytes().to_vec()
    }
    fn deserialize(bytes: &[u8]) -> Result<RistrettoPoint, DeserializationError> {
        let mut buffer = [0u8; 32];
        let n = bytes.len();

        if n == 0 || n > 32 {
            return Err(DeserializationError);
        }
        buffer[32 - n..].copy_from_slice(bytes);

        CompressedRistretto::from_slice(&buffer)
            .decompress()
            .ok_or(DeserializationError)
            .map(|ge| RistrettoPoint {
                purpose: "deserialize",
                ge,
            })
    }

    fn check_point_order_equals_group_order(&self) -> bool {
        !self.is_zero()
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> RistrettoPoint {
        RistrettoPoint {
            purpose: "scalar_mul",
            ge: self.ge * *fe.fe,
        }
    }

    fn add_point(&self, other: &Self) -> RistrettoPoint {
        RistrettoPoint {
            purpose: "add_point",
            ge: self.ge + other.ge,
        }
    }

    fn sub_point(&self, other: &Self) -> RistrettoPoint {
        RistrettoPoint {
            purpose: "sub_point",
            ge: self.ge - other.ge,
        }
    }

    fn neg_point(&self) -> RistrettoPoint {
        RistrettoPoint {
            purpose: "sub_point",
            ge: -self.ge,
        }
    }

    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        self.ge *= &*scalar.fe
    }
    fn add_point_assign(&mut self, other: &Self) {
        self.ge += &other.ge
    }
    fn sub_point_assign(&mut self, other: &Self) {
        self.ge -= &other.ge
    }
    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> RistrettoPoint {
        RistrettoPoint {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &RistrettoPoint) -> bool {
        self.ge == other.ge
    }
}

impl Zeroize for RistrettoPoint {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(&mut self.ge, PK::default()) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
