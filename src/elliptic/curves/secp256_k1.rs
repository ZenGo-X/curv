#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// Secp256k1 elliptic curve utility functions (se: https://en.bitcoin.it/wiki/Secp256k1).
//
// In Cryptography utilities, we need to manipulate low level elliptic curve members as Point
// in order to perform operation on them. As the library secp256k1 expose only SecretKey and
// PublicKey, we extend those with simple codecs.
//
// The Secret Key codec: BigInt <> SecretKey
// The Public Key codec: Point <> SecretKey
//

use std::ops;
use std::ops::Deref;
use std::ptr;
use std::sync::atomic;

use generic_array::GenericArray;
use secp256k1::constants::{
    self, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::*;

use super::traits::*;

lazy_static::lazy_static! {
    static ref CURVE_ORDER: BigInt = BigInt::from_bytes(&constants::CURVE_ORDER);

    static ref GENERATOR_UNCOMRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&GENERATOR_X);
        g[33..].copy_from_slice(&GENERATOR_Y);
        g
    };

    static ref BASE_POINT2_UNCOMPRESSED: [u8; 65] = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&BASE_POINT2_X);
        g[33..].copy_from_slice(&BASE_POINT2_Y);
        g
    };

    static ref GENERATOR: Secp256k1Point = Secp256k1Point {
        purpose: "generator",
        ge: Some(PK(PublicKey::from_slice(&GENERATOR_UNCOMRESSED[..]).unwrap())),
    };

    static ref BASE_POINT2: Secp256k1Point = Secp256k1Point {
        purpose: "base_point2",
        ge: Some(PK(PublicKey::from_slice(&BASE_POINT2_UNCOMPRESSED[..]).unwrap())),
    };
}

/* X coordinate of a point of unknown discrete logarithm.
Computed using a deterministic algorithm with the generator as input.
See test_base_point2 */
const BASE_POINT2_X: [u8; 32] = [
    0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
    0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
];

const BASE_POINT2_Y: [u8; 32] = [
    0x5d, 0x41, 0xac, 0x14, 0x77, 0x61, 0x4b, 0x5c, 0x08, 0x48, 0xd5, 0x0d, 0xbd, 0x56, 0x5e, 0xa2,
    0x80, 0x7b, 0xcb, 0xa1, 0xdf, 0x0d, 0xf0, 0x7a, 0x82, 0x17, 0xe9, 0xf7, 0xf7, 0xc2, 0xbe, 0x88,
];

/// SK wraps secp256k1::SecretKey and implements Zeroize to it
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SK(pub SecretKey);
/// PK wraps secp256k1::PublicKey and implements Zeroize to it
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PK(pub PublicKey);

impl ops::Deref for SK {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::DerefMut for SK {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ops::Deref for PK {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::DerefMut for PK {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Zeroize for SK {
    fn zeroize(&mut self) {
        let sk = self.0.as_mut_ptr();
        let sk_bytes = unsafe { std::slice::from_raw_parts_mut(sk, 32) };
        sk_bytes.zeroize()
    }
}

impl Zeroize for PK {
    fn zeroize(&mut self) {
        let zeroed = unsafe { secp256k1::ffi::PublicKey::new() };
        unsafe { ptr::write_volatile(self.0.as_mut_ptr(), zeroed) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

/// K-256 curve implementation based on [secp256k1] library
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Secp256k1 {}

impl Curve for Secp256k1 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "secp256k1";
}

#[derive(Clone, Debug)]
pub struct Secp256k1Scalar {
    #[allow(dead_code)]
    purpose: &'static str,
    /// Zeroizing<SK> wraps SK and zeroize it on drop
    ///
    /// `fe` might be None — special case for scalar being zero
    fe: zeroize::Zeroizing<Option<SK>>,
}
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Point {
    #[allow(dead_code)]
    purpose: &'static str,
    ge: Option<PK>,
}

type GE = Secp256k1Point;
type FE = Secp256k1Scalar;

impl ECScalar for Secp256k1Scalar {
    type Underlying = Option<SK>;

    type ScalarLength = typenum::U32;

    fn random() -> Secp256k1Scalar {
        let sk = SK(SecretKey::new(&mut rand_legacy::thread_rng()));
        Secp256k1Scalar {
            purpose: "random",
            fe: Zeroizing::new(Some(sk)),
        }
    }

    fn zero() -> Secp256k1Scalar {
        Secp256k1Scalar {
            purpose: "zero",
            fe: Zeroizing::new(None),
        }
    }

    fn is_zero(&self) -> bool {
        self.fe.is_none()
    }

    fn from_bigint(n: &BigInt) -> Secp256k1Scalar {
        let n = n.modulus(Self::group_order());
        if n.is_zero() {
            return Secp256k1Scalar {
                purpose: "from_bigint",
                fe: Self::zero().fe,
            };
        }
        let bytes = n
            .to_bytes_array::<SECRET_KEY_SIZE>()
            .expect("n mod curve_order must be equal or less than 32 bytes");

        Secp256k1Scalar {
            purpose: "from_bigint",
            fe: Zeroizing::new(Some(SK(
                SecretKey::from_slice(&bytes).expect("fe is in (0, order) and exactly 32 bytes")
            ))),
        }
    }

    fn to_bigint(&self) -> BigInt {
        match &*self.fe {
            Some(sk) => BigInt::from_bytes(&sk[..]),
            None => BigInt::zero(),
        }
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        match &*self.fe {
            Some(s) => GenericArray::from(*s.as_ref()),
            None => GenericArray::from([0u8; 32]),
        }
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let sk = if bytes == [0; 32] {
            None
        } else {
            Some(SK(
                SecretKey::from_slice(bytes).or(Err(DeserializationError))?
            ))
        };
        Ok(Secp256k1Scalar {
            purpose: "deserialize",
            fe: sk.into(),
        })
    }

    fn add(&self, other: &Self) -> Secp256k1Scalar {
        let fe = match (&*self.fe, &*other.fe) {
            (None, right) => right.clone(),
            (left, None) => left.clone(),
            (Some(left), Some(right)) => {
                let mut res = left.clone();
                res.add_assign(&right.0[..]).ok().map(|_| res) // right might be the negation of left.
            }
        };

        Secp256k1Scalar {
            purpose: "add",
            fe: Zeroizing::new(fe),
        }
    }

    fn mul(&self, other: &Self) -> Secp256k1Scalar {
        let fe = match (&*self.fe, &*other.fe) {
            (None, _) | (_, None) => None,
            (Some(left), Some(right)) => {
                let mut res = left.clone();
                res.0
                    .mul_assign(&right.0[..])
                    .expect("Can't fail as it's a valid secret");
                Some(res)
            }
        };

        Secp256k1Scalar {
            purpose: "mul",
            fe: Zeroizing::new(fe),
        }
    }

    fn sub(&self, other: &Self) -> Secp256k1Scalar {
        let right = other.neg();
        let res = self.clone().add(&right);
        Secp256k1Scalar {
            purpose: "sub",
            fe: res.fe,
        }
    }

    fn neg(&self) -> Self {
        let fe = self.fe.deref().clone().map(|mut fe| {
            fe.negate_assign();
            fe
        });
        Secp256k1Scalar {
            purpose: "neg",
            fe: Zeroizing::new(fe),
        }
    }

    fn invert(&self) -> Option<Secp256k1Scalar> {
        let n = self.to_bigint();
        let n_inv = BigInt::mod_inv(&n, Self::group_order());
        n_inv.map(|i| Secp256k1Scalar {
            purpose: "invert",
            fe: Self::from_bigint(&i).fe,
        })
    }

    fn group_order() -> &'static BigInt {
        &CURVE_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }

    fn from_underlying(u: Self::Underlying) -> Secp256k1Scalar {
        Secp256k1Scalar {
            purpose: "from_underlying",
            fe: Zeroizing::new(u),
        }
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Secp256k1Scalar) -> bool {
        self.underlying_ref() == other.underlying_ref()
    }
}

impl ECPoint for Secp256k1Point {
    type Scalar = Secp256k1Scalar;
    type Underlying = Option<PK>;

    type CompressedPointLength = typenum::U33;
    type UncompressedPointLength = typenum::U65;

    fn zero() -> Secp256k1Point {
        Secp256k1Point {
            purpose: "zero",
            ge: None,
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_none()
    }

    fn generator() -> &'static Secp256k1Point {
        &GENERATOR
    }

    fn base_point2() -> &'static Secp256k1Point {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, NotOnCurve> {
        let vec_x = x.to_bytes();
        let vec_y = y.to_bytes();
        const COOR_SIZE: usize = (UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) / 2;
        let mut point = [0u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];
        point[0] = 0x04;
        point[1 + COOR_SIZE - vec_x.len()..1 + COOR_SIZE].copy_from_slice(&vec_x);
        point[1 + (2 * COOR_SIZE) - vec_y.len()..].copy_from_slice(&vec_y);

        debug_assert_eq!(x, &BigInt::from_bytes(&point[1..1 + COOR_SIZE]));
        debug_assert_eq!(y, &BigInt::from_bytes(&point[1 + COOR_SIZE..]));

        PublicKey::from_slice(&point)
            .map(|ge| Secp256k1Point {
                purpose: "from_coords",
                ge: Some(PK(ge)),
            })
            .map_err(|_| NotOnCurve)
    }

    fn x_coord(&self) -> Option<BigInt> {
        match &self.ge {
            Some(ge) => {
                let serialized_pk = ge.serialize_uncompressed();
                let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
                Some(BigInt::from_bytes(x))
            }
            None => None,
        }
    }

    fn y_coord(&self) -> Option<BigInt> {
        match &self.ge {
            Some(ge) => {
                let serialized_pk = ge.serialize_uncompressed();
                let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
                Some(BigInt::from_bytes(y))
            }
            None => None,
        }
    }

    fn coords(&self) -> Option<PointCoords> {
        match &self.ge {
            Some(ge) => {
                let serialized_pk = ge.serialize_uncompressed();
                let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
                let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
                Some(PointCoords {
                    x: BigInt::from_bytes(x),
                    y: BigInt::from_bytes(y),
                })
            }
            None => None,
        }
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        match self.ge {
            None => *GenericArray::from_slice(&[0u8; 33]),
            Some(ge) => *GenericArray::from_slice(&ge.serialize()),
        }
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        match self.ge {
            None => *GenericArray::from_slice(&[0u8; 65]),
            Some(ge) => *GenericArray::from_slice(&ge.serialize_uncompressed()),
        }
    }

    fn deserialize(bytes: &[u8]) -> Result<Secp256k1Point, DeserializationError> {
        if bytes == [0; 33] || bytes == [0; 65] {
            Ok(Secp256k1Point {
                purpose: "from_bytes",
                ge: None,
            })
        } else {
            let pk = PublicKey::from_slice(bytes).map_err(|_| DeserializationError)?;
            Ok(Secp256k1Point {
                purpose: "from_bytes",
                ge: Some(PK(pk)),
            })
        }
    }

    fn check_point_order_equals_group_order(&self) -> bool {
        // This curve has cofactor=1 => any nonzero point has order GROUP_ORDER
        !self.is_zero()
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> Secp256k1Point {
        let mut res = *self;
        res.scalar_mul_assign(scalar);
        Secp256k1Point {
            purpose: "mul",
            ge: res.ge,
        }
    }

    fn generator_mul(scalar: &Self::Scalar) -> Self {
        let ge = scalar
            .fe
            .as_ref()
            .map(|sk| PK(PublicKey::from_secret_key(SECP256K1, sk)));
        Secp256k1Point {
            purpose: "generator_mul",
            ge,
        }
    }

    fn add_point(&self, other: &Self) -> Secp256k1Point {
        let ge = match (&self.ge, &other.ge) {
            (None, right) => *right,
            (left, None) => *left,
            (Some(left), Some(right)) => left.combine(right).ok().map(PK), // right might be the negation of left
        };

        Secp256k1Point { purpose: "add", ge }
    }

    fn sub_point(&self, other: &Self) -> Secp256k1Point {
        let other_negated = other.neg_point();
        let ge = self.add_point(&other_negated).ge;
        Secp256k1Point { purpose: "sub", ge }
    }

    fn neg_point(&self) -> Secp256k1Point {
        let ge = self.ge.map(|mut ge| {
            ge.0.negate_assign(SECP256K1);
            ge
        });
        Secp256k1Point { purpose: "neg", ge }
    }

    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        match (&mut self.ge, &*scalar.fe) {
            (None, _) | (_, None) => {
                self.ge = None;
            }
            (Some(ge), Some(fe)) => {
                ge.0.mul_assign(SECP256K1, &fe.0[..])
                    .expect("Can't fail as it's a valid secret");
            }
        };
        self.purpose = "mul_assign";
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> Secp256k1Point {
        Secp256k1Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl PartialEq for Secp256k1Point {
    fn eq(&self, other: &Secp256k1Point) -> bool {
        self.underlying_ref() == other.underlying_ref()
    }
}

impl Zeroize for Secp256k1Point {
    fn zeroize(&mut self) {
        self.ge.zeroize()
    }
}

pub mod hash_to_curve {
    use crate::elliptic::curves::wrappers::{Point, Scalar};
    use crate::{arithmetic::traits::*, BigInt};

    use super::Secp256k1;

    /// Takes uniformly distributed bytes and produces secp256k1 point with unknown logarithm
    ///
    /// __Note:__ this function is subject to change
    pub fn generate_random_point(bytes: &[u8]) -> Point<Secp256k1> {
        let compressed_point_len = secp256k1::constants::PUBLIC_KEY_SIZE;
        let truncated = if bytes.len() > compressed_point_len - 1 {
            &bytes[0..compressed_point_len - 1]
        } else {
            bytes
        };
        let mut buffer = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        buffer[0] = 0x2;
        buffer[1..1 + truncated.len()].copy_from_slice(truncated);
        if let Ok(point) = Point::from_bytes(&buffer) {
            return point;
        }

        let bn = BigInt::from_bytes(bytes);
        let two = BigInt::from(2);
        let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Secp256k1>::group_order());
        let bytes = BigInt::to_bytes(&bn_times_two);
        generate_random_point(&bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::generate_random_point;

        #[test]
        fn generates_point() {
            // Just prove that recursion terminates (for this input..)
            let _ = generate_random_point(&[1u8; 32]);
        }

        #[test]
        fn generates_different_points() {
            let point1 = generate_random_point(&[1u8; 32]);
            let point2 = generate_random_point(&[2u8; 32]);
            assert_ne!(point1, point2)
        }
    }
}

#[cfg(test)]
mod test {
    use sha2::{Digest, Sha256};

    use crate::arithmetic::*;

    use super::{ECPoint, GE};

    #[test]
    fn test_base_point2() {
        /* Show that base_point2() is returning a point of unknown discrete logarithm.
        It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
        as the initial input, until receiving a valid Secp256k1 point. */

        let base_point2 = GE::base_point2();

        let g = GE::generator();
        let hash = Sha256::digest(&g.serialize_compressed());
        let hash = Sha256::digest(&hash);
        let hash = Sha256::digest(&hash);

        assert_eq!(BigInt::from_bytes(&hash), base_point2.x_coord().unwrap());

        // check that base_point2 is indeed on the curve (from_coor() will fail otherwise)
        assert_eq!(
            &GE::from_coords(
                &base_point2.x_coord().unwrap(),
                &base_point2.y_coord().unwrap()
            )
            .unwrap(),
            base_point2
        );
    }
}
