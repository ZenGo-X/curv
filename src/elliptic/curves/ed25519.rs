/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// paper: https://ed25519.cr.yp.to/ed25519-20110926.pdf
// based on https://docs.rs/cryptoxide/0.1.0/cryptoxide/curve25519/index.html
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

use std::sync::atomic;
use std::{fmt, ops, ptr, str};

use cryptoxide::curve25519::*;
use generic_array::GenericArray;
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::traits::*;
use crate::cryptographic_primitives::hashing::Digest;
use crate::BigInt;

use super::traits::{ECPoint, ECScalar};
use crate::elliptic::curves::{Curve, DeserializationError, NotOnCurve, PointCoords};

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = Ed25519Scalar {
        purpose: "intermediate group_order",
        fe: SK(Fe::from_bytes(&[
            237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ])).into()
    }.to_bigint();

    static ref ZERO: Ed25519Point = Ed25519Point {
        purpose: "zero",
        ge: ge_scalarmult_base(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]),
    };

    static ref GENERATOR: Ed25519Point = Ed25519Point {
        purpose: "generator",
        ge: ge_scalarmult_base(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]),
    };

    static ref BASE_POINT2: Ed25519Point = {
        let bytes = GENERATOR.serialize_compressed();
        let hashed = sha2::Sha256::digest(bytes.as_ref());
        let hashed_twice = sha2::Sha256::digest(&hashed);
        let p = Ed25519Point::deserialize(&hashed_twice).unwrap();
        let eight = Ed25519Scalar::from_bigint(&BigInt::from(8));
        Ed25519Point {
            purpose: "base_point2",
            ge: p.scalar_mul(&eight).ge,
        }
    };
}

const FE_ZERO: Fe = Fe([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const TWO_TIMES_SECRET_KEY_SIZE: usize = 64;

/// Alias to [Edwards point](GeP3)
pub type PK = GeP3;
/// Wraps [Fe] and implements Zeroize to it
#[derive(Clone)]
pub struct SK(pub Fe);

impl Zeroize for SK {
    fn zeroize(&mut self) {
        self.0 .0.zeroize()
    }
}
impl ops::Deref for SK {
    type Target = Fe;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::DerefMut for SK {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Ed25519 curve implementation based on [cryptoxide] library
///
/// ## Implementation notes
/// * x coordinate
///
///   Underlying library doesn't expose x coordinate of curve point, but there's an algorithm
///   recovering x coordinate of ed25519 point from its y coordinate. Every time you call
///   `.x_coord()` or `from_coords()`, it takes y coordinate and runs `xrecover(y)` underhood. Keep
///   in mind that `xrecover` is quite expensive operation.
#[derive(Debug, PartialEq, Clone)]
pub enum Ed25519 {}

#[derive(Clone)]
pub struct Ed25519Scalar {
    purpose: &'static str,
    fe: Zeroizing<SK>,
}
#[derive(Clone, Copy)]
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
        let rnd_bn = BigInt::sample_below(Self::group_order());
        let rnd_bn_mul_8 = BigInt::mod_mul(&rnd_bn, &BigInt::from(8), Self::group_order());
        Ed25519Scalar {
            purpose: "random",
            fe: Self::from_bigint(&rnd_bn_mul_8).fe,
        }
    }

    fn zero() -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "zero",
            fe: SK(FE_ZERO).into(),
        }
    }

    fn is_zero(&self) -> bool {
        self.fe.0 == FE_ZERO
    }

    fn from_bigint(n: &BigInt) -> Ed25519Scalar {
        let mut v = BigInt::to_bytes(n);
        if v.len() > TWO_TIMES_SECRET_KEY_SIZE {
            v = v[0..TWO_TIMES_SECRET_KEY_SIZE].to_vec();
        }

        let mut template = vec![0; TWO_TIMES_SECRET_KEY_SIZE - v.len()];
        template.extend_from_slice(&v);
        v = template;
        v.reverse();
        sc_reduce(&mut v[..]);
        Ed25519Scalar {
            purpose: "from_bigint",
            fe: SK(Fe::from_bytes(&v[..])).into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        let mut t = self.fe.to_bytes().to_vec();
        t.reverse();
        BigInt::from_bytes(&t)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        GenericArray::from(self.fe.to_bytes())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        if bytes.len() != 32 {
            return Err(DeserializationError);
        }
        Ok(Ed25519Scalar {
            purpose: "deserialize",
            fe: SK(Fe::from_bytes(bytes)).into(),
        })
    }

    fn add(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "add",
            fe: Self::from_bigint(&BigInt::mod_add(
                &self.to_bigint(),
                &other.to_bigint(),
                Self::group_order(),
            ))
            .fe,
        }
    }

    fn mul(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "mul",
            fe: Self::from_bigint(&BigInt::mod_mul(
                &self.to_bigint(),
                &other.to_bigint(),
                Self::group_order(),
            ))
            .fe,
        }
    }

    fn sub(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "sub",
            fe: Self::from_bigint(&BigInt::mod_sub(
                &self.to_bigint(),
                &other.to_bigint(),
                Self::group_order(),
            ))
            .fe,
        }
    }

    fn neg(&self) -> Self {
        Ed25519Scalar {
            purpose: "neg",
            fe: Self::from_bigint(&BigInt::mod_sub(
                &Self::zero().to_bigint(),
                &self.to_bigint(),
                Self::group_order(),
            ))
            .fe,
        }
    }

    fn invert(&self) -> Option<Ed25519Scalar> {
        if self.is_zero() {
            None
        } else {
            Some(Ed25519Scalar {
                purpose: "invert",
                fe: Self::from_bigint(&BigInt::mod_inv(&self.to_bigint(), Self::group_order())?).fe,
            })
        }
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

impl fmt::Debug for Ed25519Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.fe.to_bytes()
        )
    }
}

impl PartialEq for Ed25519Scalar {
    fn eq(&self, other: &Ed25519Scalar) -> bool {
        self.fe.0 == other.fe.0
    }
}

impl fmt::Debug for Ed25519Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.ge.to_bytes()
        )
    }
}

impl PartialEq for Ed25519Point {
    fn eq(&self, other: &Ed25519Point) -> bool {
        self.ge.to_bytes() == other.ge.to_bytes()
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

    fn zero() -> Ed25519Point {
        *ZERO
    }

    fn is_zero(&self) -> bool {
        self == &*ZERO
    }

    fn generator() -> &'static Ed25519Point {
        &GENERATOR
    }

    fn base_point2() -> &'static Ed25519Point {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Ed25519Point, NotOnCurve> {
        let expected_x = xrecover(y);
        if &expected_x != x {
            return Err(NotOnCurve);
        }
        let y_bytes = y.to_bytes();
        let mut padded = match y_bytes.len() {
            n if n > 32 => return Err(NotOnCurve),
            32 => y_bytes,
            _ => {
                let mut padding = vec![0; 32 - y_bytes.len()];
                padding.extend_from_slice(&y_bytes);
                padding
            }
        };
        padded.reverse();
        Self::deserialize(&padded).map_err(|_e| NotOnCurve)
    }

    fn x_coord(&self) -> Option<BigInt> {
        let y = self.y_coord().unwrap();
        Some(xrecover(&y))
    }

    fn y_coord(&self) -> Option<BigInt> {
        let mut bytes = self.ge.to_bytes().to_vec();
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
        GenericArray::from(self.ge.to_bytes())
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        GenericArray::from(self.ge.to_bytes())
    }

    fn deserialize(bytes: &[u8]) -> Result<Ed25519Point, DeserializationError> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_32 = [0u8; 32];
        let byte_len = bytes_vec.len();
        match byte_len {
            0..=32 => {
                let mut template = vec![0; 32 - byte_len];
                template.extend_from_slice(bytes);
                let bytes_vec = template;
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(bytes_slice);
                let ge_from_bytes = PK::from_bytes_negate_vartime(&bytes_array_32);
                match ge_from_bytes {
                    Some(_x) => {
                        let ge_bytes = ge_from_bytes.unwrap().to_bytes();
                        let ge_from_bytes = PK::from_bytes_negate_vartime(&ge_bytes[..]);
                        match ge_from_bytes {
                            Some(y) => Ok(Ed25519Point {
                                purpose: "deserialize",
                                ge: y,
                            }),
                            None => Err(DeserializationError),
                        }
                    }
                    None => Err(DeserializationError),
                }
            }
            _ => {
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(bytes_slice);
                let ge_from_bytes = PK::from_bytes_negate_vartime(bytes);
                match ge_from_bytes {
                    Some(_x) => {
                        let ge_bytes = ge_from_bytes.unwrap().to_bytes();
                        let ge_from_bytes = PK::from_bytes_negate_vartime(&ge_bytes[..]);
                        match ge_from_bytes {
                            Some(y) => Ok(Ed25519Point {
                                purpose: "random",
                                ge: y,
                            }),
                            None => Err(DeserializationError),
                        }
                    }
                    None => Err(DeserializationError),
                }
            }
        }
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> Ed25519Point {
        let vec_0: [u8; 32];
        vec_0 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let p2_point = GeP2::double_scalarmult_vartime(&fe.fe.to_bytes()[..], self.ge, &vec_0[..]);
        let mut p2_bytes = p2_point.to_bytes();

        p2_bytes[31] ^= 1 << 7;

        let ge = GeP3::from_bytes_negate_vartime(&p2_bytes[..]).unwrap();

        Ed25519Point {
            purpose: "scalar_mul",
            ge,
        }
    }

    fn add_point(&self, other: &Self) -> Ed25519Point {
        let pkpk = self.ge + other.ge.to_cached();
        let mut pk_p2_bytes = pkpk.to_p2().to_bytes();
        pk_p2_bytes[31] ^= 1 << 7;
        Ed25519Point {
            purpose: "add",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn sub_point(&self, other: &Self) -> Ed25519Point {
        let pkpk = self.ge - other.ge.to_cached();
        let mut pk_p2_bytes = pkpk.to_p2().to_bytes();
        pk_p2_bytes[31] ^= 1 << 7;

        Ed25519Point {
            purpose: "sub",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn neg_point(&self) -> Self {
        ZERO.sub_point(self)
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
