#![allow(non_snake_case)]
/*
    Curv

    Copyright 2018 by Kzen Networks

    This file is part of curv library
    (https://github.com/KZen-networks/curv)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use super::curve25519_dalek::constants::BASEPOINT_ORDER;
use super::curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use super::curve25519_dalek::ristretto::CompressedRistretto;
use super::curve25519_dalek::scalar::Scalar;
use super::rand::thread_rng;
use super::traits::{ECPoint, ECScalar};
use arithmetic::traits::Converter;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use serde::de;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use BigInt;
use ErrorKey::{self, InvalidPublicKey};
pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;
use merkle::Hashable;
use ring::digest::Context;
pub type SK = Scalar;
pub type PK = CompressedRistretto;

#[derive(Clone, Debug)]
pub struct RistrettoScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug)]
pub struct RistrettoCurvPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = RistrettoCurvPoint;
pub type FE = RistrettoScalar;

impl ECScalar<SK> for RistrettoScalar {
    fn new_random() -> RistrettoScalar {
        RistrettoScalar {
            purpose: "random",
            fe: SK::random(&mut thread_rng()),
        }
    }

    fn zero() -> RistrettoScalar {
        let q_fe: FE = ECScalar::from(&FE::q());
        RistrettoScalar {
            purpose: "zero",
            fe: q_fe.get_element(),
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }
    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> RistrettoScalar {
        let mut v = BigInt::to_vec(n);
        //TODO: add consistency check for sizes max 32/ max 64
        let mut bytes_array_32: [u8; 32];
        let mut bytes_array_64: [u8; 64];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() > SECRET_KEY_SIZE && v.len() < 2 * SECRET_KEY_SIZE {
            let mut template = vec![0; 2 * SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() == SECRET_KEY_SIZE {
            bytes_array_32 = [0; SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_32.copy_from_slice(&bytes);
            bytes_array_32.reverse();
            RistrettoScalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order(bytes_array_32),
            }
        } else {
            bytes_array_64 = [0; 2 * SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_64.copy_from_slice(&bytes);
            bytes_array_64.reverse();
            RistrettoScalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order_wide(&bytes_array_64),
            }
        }
    }

    fn to_big_int(&self) -> BigInt {
        let t1 = &self.fe.to_bytes()[0..self.fe.to_bytes().len()];
        let mut t2 = t1.to_vec();
        t2.reverse();
        BigInt::from(&t2[0..self.fe.to_bytes().len()])
    }

    fn q() -> BigInt {
        let l = BASEPOINT_ORDER;
        let l_fe = RistrettoScalar {
            purpose: "q",
            fe: l,
        };
        l_fe.to_big_int()
    }

    fn add(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "add",
            fe: &self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "mul",
            fe: &self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "sub",
            fe: &self.get_element() - other,
        }
    }

    fn invert(&self) -> RistrettoScalar {
        let inv: SK = self.get_element().invert();
        RistrettoScalar {
            purpose: "invert",
            fe: inv,
        }
    }
}

impl Mul<RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;
    fn mul(self, other: RistrettoScalar) -> RistrettoScalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;
    fn mul(self, other: &'o RistrettoScalar) -> RistrettoScalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;
    fn add(self, other: RistrettoScalar) -> RistrettoScalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;
    fn add(self, other: &'o RistrettoScalar) -> RistrettoScalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for RistrettoScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for RistrettoScalar {
    fn deserialize<D>(deserializer: D) -> Result<RistrettoScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = RistrettoScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<RistrettoScalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for RistrettoScalar {
    fn eq(&self, other: &RistrettoScalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl PartialEq for RistrettoCurvPoint {
    fn eq(&self, other: &RistrettoCurvPoint) -> bool {
        self.get_element() == other.get_element()
    }
}

impl RistrettoCurvPoint {
    pub fn base_point2() -> RistrettoCurvPoint {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&vec![&g.x_coor()]);
        let bytes = BigInt::to_vec(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        RistrettoCurvPoint {
            purpose: "random",
            ge: h.get_element(),
        }
    }
}
impl ECPoint<PK, SK> for RistrettoCurvPoint {
    fn generator() -> RistrettoCurvPoint {
        RistrettoCurvPoint {
            purpose: "base_fe",
            ge: RISTRETTO_BASEPOINT_COMPRESSED,
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn x_coor(&self) -> BigInt {
        /* taken from https://doc-internal.dalek.rs/src/curve25519_dalek/edwards.rs.html#144
        let y = self.ge.as_bytes().clone();
        let Y = SK::from_bytes_mod_order(y);
        let Z = SK::one();
        let YY = Y*Y;
        let u = &YY - &Z;
        let v = &(&YY * &constants::EDWARDS_D) + &Z;
        let (is_nonzero_square, mut X) = sqrt_ratio(&u, &v);
        */
        //TODO: find a way to return x-coor
        let field_y = self.ge.as_bytes();
        BigInt::from(field_y[0..field_y.len()].as_ref())
    }

    fn y_coor(&self) -> BigInt {
        let field_y = self.ge.as_bytes();
        BigInt::from(field_y[0..field_y.len()].as_ref())
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from(self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref())
    }
    fn from_bytes(bytes: &[u8]) -> Result<RistrettoCurvPoint, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_32 = [0u8; 32];
        let byte_len = bytes_vec.len();
        match byte_len {
            0...32 => {
                let mut template = vec![0; 32 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let r_point: PK = CompressedRistretto::from_slice(&bytes_array_32);
                let r_point_compress = r_point.decompress();
                match r_point_compress {
                    Some(x) => {
                        let new_point = RistrettoCurvPoint {
                            purpose: "random",
                            ge: x.compress(),
                        };
                        Ok(new_point)
                    }
                    None => Err(InvalidPublicKey),
                }
            }

            _ => {
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let r_point: PK = CompressedRistretto::from_slice(&bytes_array_32);
                let r_point_compress = r_point.decompress();
                match r_point_compress {
                    Some(x) => {
                        let new_point = RistrettoCurvPoint {
                            purpose: "random",
                            ge: x.compress(),
                        };
                        Ok(new_point)
                    }
                    None => Err(InvalidPublicKey),
                }
            }
        }
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        let result = self.ge.to_bytes();
        result.to_vec()
    }

    fn scalar_mul(&self, fe: &SK) -> RistrettoCurvPoint {
        let skpk = fe * (self.ge.decompress().unwrap());
        RistrettoCurvPoint {
            purpose: "scalar_point_mul",
            ge: skpk.compress(),
        }
    }

    fn add_point(&self, other: &PK) -> RistrettoCurvPoint {
        let pkpk = self.ge.decompress().unwrap() + other.decompress().unwrap();
        RistrettoCurvPoint {
            purpose: "combine",
            ge: pkpk.compress(),
        }
    }

    fn sub_point(&self, other: &PK) -> RistrettoCurvPoint {
        let pkpk = self.ge.decompress().unwrap() - other.decompress().unwrap();
        RistrettoCurvPoint {
            purpose: "sub",
            ge: pkpk.compress(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> RistrettoCurvPoint {
        unimplemented!();
    }
}

impl Mul<RistrettoScalar> for RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn mul(self, other: RistrettoScalar) -> RistrettoCurvPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o RistrettoScalar> for RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn mul(self, other: &'o RistrettoScalar) -> RistrettoCurvPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o RistrettoScalar> for &'o RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn mul(self, other: &'o RistrettoScalar) -> RistrettoCurvPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<RistrettoCurvPoint> for RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn add(self, other: RistrettoCurvPoint) -> RistrettoCurvPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o RistrettoCurvPoint> for RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn add(self, other: &'o RistrettoCurvPoint) -> RistrettoCurvPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o RistrettoCurvPoint> for &'o RistrettoCurvPoint {
    type Output = RistrettoCurvPoint;
    fn add(self, other: &'o RistrettoCurvPoint) -> RistrettoCurvPoint {
        self.add_point(&other.get_element())
    }
}

impl Hashable for RistrettoCurvPoint {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.update(&bytes);
    }
}

impl Serialize for RistrettoCurvPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RistrettoCurvPoint", 2)?;
        state.serialize_field("x", &self.x_coor().to_hex())?;
        state.serialize_field("y", &self.y_coor().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RistrettoCurvPoint {
    fn deserialize<D>(deserializer: D) -> Result<RistrettoCurvPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RistrettoCurvPointVisitor)
    }
}

struct RistrettoCurvPointVisitor;

impl<'de> Visitor<'de> for RistrettoCurvPointVisitor {
    type Value = RistrettoCurvPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("RistrettoCurvPoint")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<RistrettoCurvPoint, E::Error> {
        let mut x = String::new();
        let mut y = String::new();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key.as_ref() {
                "x" => x = String::from(v),
                "y" => y = String::from(v),
                _ => panic!("Serialization failed!"),
            }
        }

        let bx = BigInt::from_hex(&x);
        let by = BigInt::from_hex(&y);

        Ok(RistrettoCurvPoint::from_coor(&bx, &by))
    }
}

#[cfg(feature = "curveristretto")]
#[cfg(test)]
mod tests {

    use super::RistrettoCurvPoint;
    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use BigInt;
    use {FE, GE};

    #[test]
    fn test_from_mpz() {
        let rand_scalar: FE = ECScalar::new_random();
        let rand_bn = rand_scalar.to_big_int();
        let rand_scalar2: FE = ECScalar::from(&rand_bn);
        assert_eq!(rand_scalar, rand_scalar2);
    }

    #[test]
    fn test_from_slice() {
        let point: GE = GE::base_point2();
        let point_bn = point.bytes_compressed_to_big_int();
        let point_bytes = BigInt::to_vec(&point_bn);
        let point_reconstruct = GE::from_bytes(&point_bytes[..]).expect("bad encoding of point");
        assert_eq!(point_reconstruct, point);
    }

    #[test]
    #[should_panic]
    fn test_from_slice_bad_point() {
        // let rng = &mut thread_rng();
        //  rng.fill(&mut scalar_bytes);
        let scalar_bytes = [
            47, 99, 244, 119, 185, 184, 77, 196, 233, 191, 206, 168, 191, 24, 226, 7, 254, 11, 131,
            172, 57, 35, 110, 9, 103, 25, 98, 249, 219, 248, 33, 115,
        ];
        GE::from_bytes(&scalar_bytes[..]).expect("bad encoding of point");
    }
    // this test fails once in a while.
    #[test]
    fn test_minus_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let b_bn = b.to_big_int();
        let order = FE::q();
        let minus_b = BigInt::mod_sub(&order, &b_bn, &order);
        let a_minus_b = BigInt::mod_add(&a.to_big_int(), &minus_b, &order);
        let a_minus_b_fe: FE = ECScalar::from(&a_minus_b);
        let base: GE = ECPoint::generator();
        let point_ab1 = base.clone() * a_minus_b_fe;
        let point_a = base.clone() * a;
        let point_b = base.clone() * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_invert() {
        let a: FE = ECScalar::new_random();
        let a_bn = a.to_big_int();
        let a_inv = a.invert();
        let a_inv_bn_1 = a_bn.invert(&FE::q()).unwrap();
        let a_inv_bn_2 = a_inv.to_big_int();
        assert_eq!(a_inv_bn_1, a_inv_bn_2);
    }

    #[test]
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = RistrettoCurvPoint::from_bytes(&test_vec);
        assert!(result.is_ok())
    }

}
