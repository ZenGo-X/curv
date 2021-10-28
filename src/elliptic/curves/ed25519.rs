/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// paper: https://ed25519.cr.yp.to/ed25519-20110926.pdf
// based on https://docs.rs/curve25519-dalek/3.2.0/curve25519_dalek/index.html
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

use super::{
    traits::{ECPoint, ECScalar},
    Curve, DeserializationError, NotOnCurve, PointCoords,
};
use crate::{arithmetic::traits::*, cryptographic_primitives::hashing::Digest, BigInt};
use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use generic_array::GenericArray;
use std::{convert::TryInto, ptr, str, sync::atomic};
use zeroize::{Zeroize, Zeroizing};

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = Ed25519Scalar {
        purpose: "intermediate group_order",
        fe: constants::BASEPOINT_ORDER.into()
    }.to_bigint();

    static ref ZERO: Ed25519Point = Ed25519Point {
        purpose: "zero",
        ge: EdwardsPoint::identity(),
    };

    static ref FE_ZERO: SK = Scalar::zero();

    static ref BASE_POINT2: Ed25519Point = {
        let bytes = GENERATOR.serialize_compressed();
        let hashed = sha2::Sha256::digest(bytes.as_ref());
        let hashed_twice = sha2::Sha256::digest(&hashed);
        let p = CompressedEdwardsY::from_slice(&*hashed_twice).decompress().unwrap();
        let eight = Scalar::from(8u8);
        Ed25519Point {
            purpose: "base_point2",
            ge: p * eight,
        }
    };
}

const GENERATOR: Ed25519Point = Ed25519Point {
    purpose: "generator",
    ge: constants::ED25519_BASEPOINT_POINT,
};

const TWO_TIMES_SECRET_KEY_SIZE: usize = 64;

/// Alias to [Edwards point](EdwardsPoint)
pub type PK = EdwardsPoint;
pub type SK = Scalar;

/// Ed25519 curve implementation based on [cryptoxide] library
///
/// ## Implementation notes
/// * x coordinate
///
///   Underlying library doesn't expose x coordinate of curve point, but there's an algorithm
///   recovering x coordinate of ed25519 point from its y coordinate. Every time you call
///   `.x_coord()` or `from_coords()`, it takes y coordinate and runs `xrecover(y)` underhood. Keep
///   in mind that `xrecover` is quite expensive operation.
pub enum Ed25519 {}

#[derive(Clone, Debug)]
pub struct Ed25519Scalar {
    purpose: &'static str,
    fe: Zeroizing<SK>,
}
#[derive(Clone, Debug, Copy)]
pub struct Ed25519Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Ed25519Point;
pub type FE = Ed25519Scalar;

impl Curve for Ed25519 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "ed25519";
}

impl ECScalar for Ed25519Scalar {
    type Underlying = SK;

    type ScalarLength = typenum::U32;

    // we chose to multiply by 8 (co-factor) all group elements to work in the prime order sub group.
    // each random fe is having its 3 first bits zeroed
    fn random() -> Ed25519Scalar {
        let scalar = Scalar::random(&mut rand::thread_rng());
        Ed25519Scalar {
            purpose: "random",
            fe: Zeroizing::new(scalar),
        }
    }

    fn zero() -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "zero",
            fe: (*FE_ZERO).into(),
        }
    }

    fn is_zero(&self) -> bool {
        *self.fe == *FE_ZERO
    }

    fn from_bigint(n: &BigInt) -> Ed25519Scalar {
        let mut v = BigInt::to_bytes(n);
        v.truncate(TWO_TIMES_SECRET_KEY_SIZE);

        let mut template = [0u8; TWO_TIMES_SECRET_KEY_SIZE];
        template[TWO_TIMES_SECRET_KEY_SIZE - v.len()..].copy_from_slice(&v);
        template.reverse();
        let scalar = Scalar::from_bytes_mod_order_wide(&template);
        Ed25519Scalar {
            purpose: "from_bigint",
            fe: scalar.into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        let mut t = self.fe.to_bytes();
        t.reverse();
        BigInt::from_bytes(&t)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        GenericArray::from(self.fe.to_bytes())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| DeserializationError)?;
        Ok(Ed25519Scalar {
            purpose: "deserialize",
            fe: SK::from_bits(arr).into(),
        })
    }

    fn add(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "add",
            fe: (*self.fe + *other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "mul",
            fe: (*self.fe * *other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "sub",
            fe: (*self.fe - *other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        Ed25519Scalar {
            purpose: "neg",
            fe: (-&*self.fe).into(),
        }
    }

    fn invert(&self) -> Option<Ed25519Scalar> {
        if self.is_zero() {
            None
        } else {
            Some(Ed25519Scalar {
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
    fn from_underlying(fe: Self::Underlying) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl PartialEq for Ed25519Scalar {
    fn eq(&self, other: &Ed25519Scalar) -> bool {
        self.fe == other.fe
    }
}

impl PartialEq for Ed25519Point {
    fn eq(&self, other: &Ed25519Point) -> bool {
        self.ge == other.ge
    }
}

impl Zeroize for Ed25519Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(&mut self.ge, GENERATOR.ge) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for Ed25519Point {
    type Underlying = PK;
    type Scalar = Ed25519Scalar;

    type CompressedPointLength = typenum::U32;
    type UncompressedPointLength = typenum::U32;

    fn zero() -> Self {
        *ZERO
    }

    fn is_zero(&self) -> bool {
        self == &*ZERO
    }

    fn generator() -> &'static Self {
        &GENERATOR
    }

    fn base_point2() -> &'static Self {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, NotOnCurve> {
        let expected_x = xrecover(y);
        if &expected_x != x {
            return Err(NotOnCurve);
        }
        let mut y_bytes = y.to_bytes_array::<32>().ok_or(NotOnCurve)?;
        y_bytes.reverse();
        Self::deserialize(&y_bytes).map_err(|_| NotOnCurve)
    }

    fn x_coord(&self) -> Option<BigInt> {
        let y = self.y_coord().unwrap();
        Some(xrecover(&y))
    }

    fn y_coord(&self) -> Option<BigInt> {
        let mut bytes = self.ge.compress().to_bytes();
        bytes.reverse();
        Some(BigInt::from_bytes(&bytes))
    }

    fn coords(&self) -> Option<PointCoords> {
        let y = self
            .y_coord()
            .expect("coordinates are always defined for edwards curves");
        Some(PointCoords { x: xrecover(&y), y })
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        GenericArray::from(self.ge.compress().0)
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        self.serialize_compressed()
    }

    fn deserialize(bytes: &[u8]) -> Result<Ed25519Point, DeserializationError> {
        let bytes_len = bytes.len();
        let mut edwards_y = CompressedEdwardsY([0; 32]);
        if bytes_len >= 32 {
            edwards_y.0.copy_from_slice(&bytes[..32]);
        } else {
            edwards_y.0[32 - bytes_len..].copy_from_slice(bytes);
        }
        let ge = edwards_y.decompress().ok_or(DeserializationError)?;
        Ok(Ed25519Point {
            purpose: "deserialize",
            ge,
        })
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> Ed25519Point {
        Ed25519Point {
            purpose: "scalar_mul",
            ge: self.ge * *fe.fe,
        }
    }

    fn generator_mul(scalar: &Self::Scalar) -> Self {
        Self {
            purpose: "generator_mul",
            ge: constants::ED25519_BASEPOINT_TABLE.basepoint_mul(&*scalar.fe), // Much faster than multiplying manually by the generator point.
        }
    }

    fn add_point(&self, other: &Self) -> Ed25519Point {
        Ed25519Point {
            purpose: "add",
            ge: self.ge + other.ge,
        }
    }

    fn sub_point(&self, other: &Self) -> Ed25519Point {
        Ed25519Point {
            purpose: "sub",
            ge: self.ge - other.ge,
        }
    }

    fn neg_point(&self) -> Self {
        Ed25519Point {
            purpose: "neg_point",
            ge: -self.ge,
        }
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> Ed25519Point {
        Ed25519Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

#[allow(clippy::many_single_char_names)]
//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
fn xrecover(y_coor: &BigInt) -> BigInt {
    //   let d = "37095705934669439343138083508754565189542113879843219016388785533085940283555";
    //   let d_bn = BigInt::from(d.as_bytes());
    let q = BigInt::from(2u32).pow(255u32) - BigInt::from(19u32);
    let one = BigInt::one();
    let d_n = -BigInt::from(121_665i32);
    let d_d = expmod(&BigInt::from(121_666), &(q.clone() - BigInt::from(2)), &q);

    let d_bn = d_n * d_d;
    let y_sqr = y_coor * y_coor;
    let u = y_sqr.clone() - one.clone();
    let v = y_sqr * d_bn + one;
    let v_inv = expmod(&v, &(q.clone() - BigInt::from(2)), &q);

    let x_sqr = u * v_inv;
    let q_plus_3_div_8 = (q.clone() + BigInt::from(3i32)) / BigInt::from(8i32);

    let mut x = expmod(&x_sqr, &q_plus_3_div_8, &q);
    if BigInt::mod_sub(&(x.clone() * x.clone()), &x_sqr, &q) != BigInt::zero() {
        let q_minus_1_div_4 = (q.clone() - BigInt::from(3i32)) / BigInt::from(4i32);
        let i = expmod(&BigInt::from(2i32), &q_minus_1_div_4, &q);
        x = BigInt::mod_mul(&x, &i, &q);
    }
    if BigInt::modulus(&x, &BigInt::from(2i32)) != BigInt::zero() {
        x = q - x.clone();
    }

    x
}

//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
fn expmod(b: &BigInt, e: &BigInt, m: &BigInt) -> BigInt {
    let one = BigInt::one();
    if e.clone() == BigInt::zero() {
        return one;
    };
    let t_temp = expmod(b, &(e.clone() / BigInt::from(2u32)), m);
    let mut t = BigInt::mod_pow(&t_temp, &BigInt::from(2u32), m);

    if BigInt::modulus(e, &BigInt::from(2)) != BigInt::zero() {
        t = BigInt::mod_mul(&t, b, m);
    }
    t
}
