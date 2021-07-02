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

use std::ops::{self, Deref};
use std::ptr;
use std::sync::atomic;

use rand::thread_rng;
use secp256k1::constants::{
    self, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
use secp256k1::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::*;

use super::traits::*;

lazy_static::lazy_static! {
    static ref CONTEXT: secp256k1::Secp256k1<secp256k1::VerifyOnly> = secp256k1::Secp256k1::verification_only();

    static ref CURVE_ORDER: BigInt = BigInt::from_bytes(&constants::CURVE_ORDER);

    static ref GENERATOR_UNCOMRESSED: Vec<u8> = {
        let mut g = vec![4_u8];
        g.extend_from_slice(&GENERATOR_X);
        g.extend_from_slice(&GENERATOR_Y);
        g
    };

    static ref BASE_POINT2_UNCOMPRESSED: Vec<u8> = {
        let mut g = vec![4_u8];
        g.extend_from_slice(BASE_POINT2_X.as_ref());
        g.extend_from_slice(BASE_POINT2_Y.as_ref());
        g
    };

    static ref GENERATOR: Secp256k1Point = Secp256k1Point {
        purpose: "generator",
        ge: Some(PK(PublicKey::from_slice(&GENERATOR_UNCOMRESSED).unwrap())),
    };

    static ref BASE_POINT2: Secp256k1Point = Secp256k1Point {
        purpose: "base_point2",
        ge: Some(PK(PublicKey::from_slice(&BASE_POINT2_UNCOMPRESSED).unwrap())),
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
#[derive(Clone, PartialEq, Debug)]
pub struct SK(pub SecretKey);
/// PK wraps secp256k1::PublicKey and implements Zeroize to it
#[derive(Copy, Clone, PartialEq, Debug)]
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
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Secp256k1 {}

impl Curve for Secp256k1 {
    type Point = GE;
    type Scalar = FE;

    fn curve_name() -> &'static str {
        "secp256k1"
    }
}

#[derive(Clone, Debug)]
pub struct Secp256k1Scalar {
    purpose: &'static str,
    /// Zeroizing<SK> wraps SK and zeroize it on drop
    ///
    /// `fe` might be None — special case for scalar being zero
    fe: zeroize::Zeroizing<Option<SK>>,
}
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Point {
    purpose: &'static str,
    ge: Option<PK>,
}

type GE = Secp256k1Point;
type FE = Secp256k1Scalar;

impl ECScalar for Secp256k1Scalar {
    type Underlying = Option<SK>;

    fn random() -> Secp256k1Scalar {
        let sk = SK(SecretKey::new(&mut thread_rng()));
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
        if n.is_zero() {
            return Self::zero();
        }

        let curve_order = Self::curve_order();
        let n_reduced = n.modulus(curve_order);
        let bytes = BigInt::to_bytes(&n_reduced);

        let bytes = if bytes.len() < SECRET_KEY_SIZE {
            let mut zero_prepended = vec![0; SECRET_KEY_SIZE - bytes.len()];
            zero_prepended.extend_from_slice(&bytes);
            zero_prepended
        } else {
            bytes
        };

        Secp256k1Scalar {
            purpose: "from_bigint",
            fe: Zeroizing::new(SecretKey::from_slice(&bytes).map(SK).ok()),
        }
    }

    fn to_bigint(&self) -> BigInt {
        match self.fe.deref() {
            Some(sk) => BigInt::from_bytes(&sk[..]),
            None => BigInt::zero(),
        }
    }

    fn add(&self, other: &Self) -> Secp256k1Scalar {
        // TODO: use add_assign?
        //  https://docs.rs/secp256k1/0.20.3/secp256k1/key/struct.SecretKey.html#method.add_assign
        let n = BigInt::mod_add(&self.to_bigint(), &other.to_bigint(), Self::curve_order());
        Secp256k1Scalar {
            purpose: "add",
            fe: Self::from_bigint(&n).fe,
        }
    }

    fn mul(&self, other: &Self) -> Secp256k1Scalar {
        // TODO: use mul_assign?
        //  https://docs.rs/secp256k1/0.20.3/secp256k1/key/struct.SecretKey.html#method.mul_assign
        let n = BigInt::mod_mul(&self.to_bigint(), &other.to_bigint(), Self::curve_order());
        Secp256k1Scalar {
            purpose: "mul",
            fe: Self::from_bigint(&n).fe,
        }
    }

    fn sub(&self, other: &Self) -> Secp256k1Scalar {
        // TODO: use negate+add_assign?
        //  https://docs.rs/secp256k1/0.20.3/secp256k1/key/struct.SecretKey.html#method.negate_assign
        //  https://docs.rs/secp256k1/0.20.3/secp256k1/key/struct.SecretKey.html#method.add_assign
        let n = BigInt::mod_sub(&self.to_bigint(), &other.to_bigint(), Self::curve_order());
        Secp256k1Scalar {
            purpose: "sub",
            fe: Self::from_bigint(&n).fe,
        }
    }

    fn neg(&self) -> Self {
        let n = BigInt::mod_sub(&BigInt::zero(), &self.to_bigint(), Self::curve_order());
        Secp256k1Scalar {
            purpose: "neg",
            fe: Self::from_bigint(&n).fe,
        }
    }

    fn invert(&self) -> Option<Secp256k1Scalar> {
        let n = self.to_bigint();
        let n_inv = BigInt::mod_inv(&n, Self::curve_order());
        n_inv.map(|i| Secp256k1Scalar {
            purpose: "invert",
            fe: Self::from_bigint(&i).fe,
        })
    }

    fn curve_order() -> &'static BigInt {
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
        let mut vec_x = BigInt::to_bytes(x);
        let mut vec_y = BigInt::to_bytes(y);
        let coor_size = (UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) / 2;

        if vec_x.len() < coor_size {
            // pad
            let mut x_padded = vec![0; coor_size - vec_x.len()];
            x_padded.extend_from_slice(&vec_x);
            vec_x = x_padded
        }

        if vec_y.len() < coor_size {
            // pad
            let mut y_padded = vec![0; coor_size - vec_y.len()];
            y_padded.extend_from_slice(&vec_y);
            vec_y = y_padded
        }

        assert_eq!(x, &BigInt::from_bytes(vec_x.as_ref()));
        assert_eq!(y, &BigInt::from_bytes(vec_y.as_ref()));

        let mut v = vec![4_u8];
        v.extend(vec_x);
        v.extend(vec_y);

        PublicKey::from_slice(&v)
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

    fn serialize(&self, compressed: bool) -> Option<Vec<u8>> {
        let ge = self.ge.as_ref()?;
        if compressed {
            Some(ge.serialize().to_vec())
        } else {
            // TODO: why not using ge.serialize_uncompressed()?
            //  https://docs.rs/secp256k1/0.20.3/secp256k1/key/struct.PublicKey.html#method.serialize_uncompressed
            let mut v = vec![4_u8];
            let x_vec = BigInt::to_bytes(
                &self
                    .x_coord()
                    .expect("guaranteed by the first line of this function"),
            );
            let y_vec = BigInt::to_bytes(
                &self
                    .y_coord()
                    .expect("guaranteed by the first line of this function"),
            );

            let mut raw_x: Vec<u8> = Vec::new();
            let mut raw_y: Vec<u8> = Vec::new();
            raw_x.extend(vec![0u8; 32 - x_vec.len()]);
            raw_x.extend(x_vec);

            raw_y.extend(vec![0u8; 32 - y_vec.len()]);
            raw_y.extend(y_vec);

            v.extend(raw_x);
            v.extend(raw_y);
            Some(v)
        }
    }

    fn deserialize(bytes: &[u8]) -> Result<Secp256k1Point, DeserializationError> {
        let pk = PublicKey::from_slice(bytes).map_err(|_| DeserializationError)?;
        Ok(Secp256k1Point {
            purpose: "from_bytes",
            ge: Some(PK(pk)),
        })
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> Secp256k1Point {
        let mut new_point = match &self.ge {
            Some(ge) => *ge,
            None => {
                // Point is zero => O * a = O
                return Secp256k1Point {
                    purpose: "mul",
                    ge: None,
                };
            }
        };
        let scalar = match scalar.fe.deref() {
            Some(s) => s,
            None => {
                // Scalar is zero => p * 0 = O
                return Secp256k1Point {
                    purpose: "mul",
                    ge: None,
                };
            }
        };
        let result = new_point.mul_assign(&CONTEXT, &scalar[..]);
        if result.is_err() {
            // Multiplication resulted into zero point
            return Secp256k1Point {
                purpose: "mul",
                ge: None,
            };
        }

        Secp256k1Point {
            purpose: "mul",
            ge: Some(new_point),
        }
    }

    fn add_point(&self, other: &Self) -> Secp256k1Point {
        let ge1 = match &self.ge {
            Some(ge) => ge,
            None => {
                // Point1 is zero => O + p2 = p2
                return Secp256k1Point {
                    purpose: "add",
                    ge: other.ge,
                };
            }
        };
        let ge2 = match &other.ge {
            Some(ge) => ge,
            None => {
                // Point2 is zero => p1 + O = p1
                return Secp256k1Point {
                    purpose: "add",
                    ge: Some(*ge1),
                };
            }
        };
        Secp256k1Point {
            purpose: "add",
            ge: ge1.combine(ge2).map(PK).ok(),
        }
    }

    fn sub_point(&self, other: &Self) -> Secp256k1Point {
        let mut ge2_negated = match &other.ge {
            Some(ge) => *ge,
            None => {
                // Point2 is zero => p1 - O = p1
                return Secp256k1Point {
                    purpose: "sub",
                    ge: self.ge,
                };
            }
        };
        ge2_negated.negate_assign(&CONTEXT);

        let ge1 = match &self.ge {
            Some(ge) => ge,
            None => {
                // Point1 is zero => O - p2 = -p2
                return Secp256k1Point {
                    purpose: "sub",
                    ge: Some(ge2_negated),
                };
            }
        };

        Secp256k1Point {
            purpose: "sub",
            ge: ge1.combine(&ge2_negated).map(PK).ok(),
        }
    }

    fn neg_point(&self) -> Secp256k1Point {
        Secp256k1Point {
            purpose: "neg",
            ge: match self.ge {
                Some(mut ge) => {
                    ge.negate_assign(&CONTEXT);
                    Some(ge)
                }
                None => {
                    // Point is zero => -O = O
                    None
                }
            },
        }
    }

    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        let ge = match self.ge.as_mut() {
            Some(ge) => ge,
            None => {
                // Point is zero => O * s = O
                self.ge = None;
                return;
            }
        };

        let fe = match scalar.fe.as_ref() {
            Some(fe) => fe,
            None => {
                // Scalar is zero => p * 0 = O
                self.ge = None;
                return;
            }
        };

        if let Err(_) = ge.mul_assign(&CONTEXT, &fe[..]) {
            // Multiplication resulted into zero
            self.ge = None
        }
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

#[cfg(test)]
mod test {
    use std::iter;

    use crate::elliptic::curves::traits::*;
    use crate::BigInt;

    use super::{FE, GE};

    #[test]
    fn valid_zero_point() {
        let zero = GE::zero();
        assert!(zero.is_zero());
        assert_eq!(zero, GE::zero());
    }

    #[test]
    fn zero_point_arithmetic() {
        let zero_point = GE::zero();
        let point = GE::generator().scalar_mul(&FE::random());

        assert_eq!(zero_point.add_point(&point), point, "O + P = P");
        assert_eq!(point.add_point(&zero_point), point, "P + O = P");

        let point_neg = point.neg_point();
        assert!(point.add_point(&point_neg).is_zero(), "P + (-P) = O");
        assert!(point.sub_point(&point).is_zero(), "P - P = O");

        let zero_scalar = FE::zero();
        assert!(point.scalar_mul(&zero_scalar).is_zero(), "P * 0 = O");
        let scalar = FE::random();
        assert!(zero_point.scalar_mul(&scalar).is_zero(), "O * s = O")
    }

    #[test]
    fn scalar_modulo_curve_order() {
        let n = FE::curve_order();
        let s = FE::from_bigint(n);
        assert!(s.is_zero());

        let s = FE::from_bigint(&(n + 1));
        assert_eq!(s, FE::from_bigint(&BigInt::from(1)));
    }

    #[test]
    fn zero_scalar_arithmetic() {
        let s = FE::random();
        let z = FE::zero();
        assert!(s.mul(&z).is_zero());
        assert!(z.mul(&s).is_zero());
        assert_eq!(s.add(&z), s);
        assert_eq!(z.add(&s), s);
    }

    #[test]
    fn point_addition_multiplication() {
        let point = GE::generator().scalar_mul(&FE::random());
        assert!(!point.is_zero(), "G * s != O");

        let addition = iter::successors(Some(point), |p| Some(p.add_point(&point)))
            .take(10)
            .collect::<Vec<_>>();
        let multiplication = (1..=10)
            .map(|i| FE::from_bigint(&BigInt::from(i)))
            .map(|s| point.scalar_mul(&s))
            .collect::<Vec<_>>();
        assert_eq!(addition, multiplication);
    }

    #[test]
    fn serialize_deserialize() {
        let point = GE::generator().scalar_mul(&FE::random());
        let bytes = point
            .serialize(true)
            .expect("point has coordinates => must be serializable");
        let deserialized = GE::deserialize(&bytes).unwrap();
        assert_eq!(point, deserialized);

        let bytes = point
            .serialize(false)
            .expect("point has coordinates => must be serializable");
        let deserialized = GE::deserialize(&bytes).unwrap();
        assert_eq!(point, deserialized);
    }

    // #[test]
    // fn test_base_point2() {
    //     /* Show that base_point2() is returning a point of unknown discrete logarithm.
    //     It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
    //     as the initial input, until receiving a valid Secp256k1 point. */
    //
    //     let base_point2 = GE::base_point2();
    //
    //     let g = GE::generator();
    //     let mut hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
    //     hash = HSha256::create_hash(&[&hash]);
    //     hash = HSha256::create_hash(&[&hash]);
    //
    //     assert_eq!(hash, base_point2.x_coor().unwrap(),);
    //
    //     // check that base_point2 is indeed on the curve (from_coor() will fail otherwise)
    //     assert_eq!(
    //         Secp256k1Point::from_coor(
    //             &base_point2.x_coor().unwrap(),
    //             &base_point2.y_coor().unwrap()
    //         ),
    //         base_point2
    //     );
    // }
}
