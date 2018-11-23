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

// paper: https://ed25519.cr.yp.to/ed25519-20110926.pdf
// based on https://docs.rs/cryptoxide/0.1.0/cryptoxide/curve25519/index.html
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

use std::fmt::Debug;
pub const SECRET_KEY_SIZE: usize = 32;
use super::cryptoxide::curve25519::*;
use super::rand::{thread_rng, Rng};
use super::traits::{ECPoint, ECScalar};
use arithmetic::traits::Converter;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use merkle::Hashable;
use ring::digest::Context;
use serde::de;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use BigInt;
use ErrorKey::{self, InvalidPublicKey};
pub type SK = Fe;
pub type PK = GeP3;

#[derive(Clone)]
pub struct Ed25519Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone)]
pub struct Ed25519Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Ed25519Point;
pub type FE = Ed25519Scalar;

impl ECScalar<SK> for Ed25519Scalar {
    fn new_random() -> Ed25519Scalar {
        let mut scalar_bytes = [0u8; 32];
        let rng = &mut thread_rng();
        rng.fill(&mut scalar_bytes);
        let rand_fe = SK::from_bytes(&scalar_bytes);
        Ed25519Scalar {
            purpose: "random",
            fe: rand_fe,
        }
    }

    fn zero() -> Ed25519Scalar {
        let q_fe: FE = ECScalar::from(&FE::q());
        Ed25519Scalar {
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

    fn from(n: &BigInt) -> Ed25519Scalar {
        let mut v = BigInt::to_vec(n);
        //TODO: add consistency check for sizes max 32/ max 64
        let mut bytes_array_32: [u8; 32];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        bytes_array_32 = [0; SECRET_KEY_SIZE];
        let bytes = &v[..];
        bytes_array_32.copy_from_slice(&bytes);
        bytes_array_32.reverse();
        Ed25519Scalar {
            purpose: "from_big_int",
            fe: SK::from_bytes(&bytes_array_32),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let t1 = &self.fe.to_bytes()[0..self.fe.to_bytes().len()];
        let mut t2 = t1.to_vec();
        t2.reverse();
        BigInt::from(&t2[0..self.fe.to_bytes().len()])
    }

    fn q() -> BigInt {
        let q_bytes_array: [u8; 32];
        q_bytes_array = [
            237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
        ];
        let l_fe = SK::from_bytes(&q_bytes_array);
        let l_fe = Ed25519Scalar {
            purpose: "q",
            fe: l_fe,
        };
        l_fe.to_big_int()
    }

    fn add(&self, other: &SK) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "add",
            fe: self.get_element().clone() + other.clone(),
        }
    }

    fn mul(&self, other: &SK) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "mul",
            fe: self.get_element().clone() * other.clone(),
        }
    }

    fn sub(&self, other: &SK) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "sub",
            fe: self.get_element().clone() - other.clone(),
        }
    }

    fn invert(&self) -> Ed25519Scalar {
        let inv: SK = self.get_element().invert();
        Ed25519Scalar {
            purpose: "invert",
            fe: inv,
        }
    }
}

impl Debug for Ed25519Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.fe.to_bytes()
        )
    }
}

impl Mul<Ed25519Scalar> for Ed25519Scalar {
    type Output = Ed25519Scalar;
    fn mul(self, other: Ed25519Scalar) -> Ed25519Scalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Ed25519Scalar> for Ed25519Scalar {
    type Output = Ed25519Scalar;
    fn mul(self, other: &'o Ed25519Scalar) -> Ed25519Scalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<Ed25519Scalar> for Ed25519Scalar {
    type Output = Ed25519Scalar;
    fn add(self, other: Ed25519Scalar) -> Ed25519Scalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o Ed25519Scalar> for Ed25519Scalar {
    type Output = Ed25519Scalar;
    fn add(self, other: &'o Ed25519Scalar) -> Ed25519Scalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for Ed25519Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Ed25519Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Ed25519Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Ed25519Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Ed25519Scalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl Debug for Ed25519Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.ge.to_bytes()
        )
    }
}
impl Ed25519Point {
    pub fn base_point2() -> Ed25519Point {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&vec![&g.x_coor()]);
        let bytes = BigInt::to_vec(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        Ed25519Point {
            purpose: "random",
            ge: h.get_element(),
        }
    }
}
impl ECPoint<PK, SK> for Ed25519Point {
    fn generator() -> Ed25519Point {
        let g_bytes_array: [u8; 32];
        g_bytes_array = [
            88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
            102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        ];
        Ed25519Point {
            purpose: "base_fe",
            ge: PK::from_bytes_negate_vartime(&g_bytes_array).unwrap(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn x_coor(&self) -> BigInt {
        //TODO: find a way to return x-coor
        let field_y = self.ge.to_bytes();
        BigInt::from(field_y[0..field_y.len()].as_ref())
    }

    fn y_coor(&self) -> BigInt {
        self.x_coor()
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from(self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref())
    }

    // we chose to multiply by 8 all group elements to work in the prime order sub group.
    // function scalar mul takes scalar s and return 8sG.
    // function from bytes takes byte array, convert to point R and return 8R
    fn from_bytes(bytes: &[u8]) -> Result<Ed25519Point, ErrorKey> {
        let ge_from_bytes = PK::from_bytes_negate_vartime(bytes);
        match ge_from_bytes {
            Some(_x) => {
                let vec_1: [u8; 32];
                vec_1 = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1,
                ];
                let v1_bn = BigInt::from(&vec_1[..]);
                let fe_1: FE = ECScalar::from(&v1_bn);
                let new_point = Ed25519Point {
                    purpose: "random",
                    ge: ge_from_bytes.unwrap(),
                };
                let new_point_8 = new_point.scalar_mul(&fe_1.get_element());
                Ok(new_point_8)
            }
            None => Err(InvalidPublicKey),
        }
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        let result = self.ge.to_bytes();
        result.to_vec()
    }

    fn scalar_mul(&self, fe: &SK) -> Ed25519Point {
        let vec_8: [u8; 32];
        vec_8 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 8,
        ];
        let v8_bn = BigInt::from(&vec_8[..]);
        let fe_8: FE = ECScalar::from(&v8_bn);
        let scalar_mul_8 = fe_8.get_element() * fe.clone();
        let sk_bytes = scalar_mul_8.to_bytes();
        Ed25519Point {
            purpose: "scalar_point_mul",
            ge: ge_scalarmult_base(&sk_bytes),
        }
    }

    fn add_point(&self, other: &PK) -> Ed25519Point {
        let pkpk = self.ge.clone() + other.to_cached();
        let pk_p2_bytes = pkpk.to_p2().to_bytes();
        Ed25519Point {
            purpose: "combine",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Ed25519Point {
        let pkpk = self.ge.clone() - other.to_cached();
        let pk_p2_bytes = pkpk.to_p2().to_bytes();
        Ed25519Point {
            purpose: "sub",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> Ed25519Point {
        unimplemented!();
    }
}

impl Mul<Ed25519Scalar> for Ed25519Point {
    type Output = Ed25519Point;
    fn mul(self, other: Ed25519Scalar) -> Ed25519Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Ed25519Scalar> for Ed25519Point {
    type Output = Ed25519Point;
    fn mul(self, other: &'o Ed25519Scalar) -> Ed25519Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Ed25519Scalar> for &'o Ed25519Point {
    type Output = Ed25519Point;
    fn mul(self, other: &'o Ed25519Scalar) -> Ed25519Point {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Ed25519Point> for Ed25519Point {
    type Output = Ed25519Point;
    fn add(self, other: Ed25519Point) -> Ed25519Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Ed25519Point> for Ed25519Point {
    type Output = Ed25519Point;
    fn add(self, other: &'o Ed25519Point) -> Ed25519Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Ed25519Point> for &'o Ed25519Point {
    type Output = Ed25519Point;
    fn add(self, other: &'o Ed25519Point) -> Ed25519Point {
        self.add_point(&other.get_element())
    }
}

impl Hashable for Ed25519Point {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.update(&bytes);
    }
}

impl Serialize for Ed25519Point {
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

impl<'de> Deserialize<'de> for Ed25519Point {
    fn deserialize<D>(deserializer: D) -> Result<Ed25519Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RistrettoCurvPointVisitor)
    }
}

struct RistrettoCurvPointVisitor;

impl<'de> Visitor<'de> for RistrettoCurvPointVisitor {
    type Value = Ed25519Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("RistrettoCurvPoint")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Ed25519Point, E::Error> {
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

        Ok(Ed25519Point::from_coor(&bx, &by))
    }
}

#[cfg(test)]
mod tests {
    use super::Ed25519Point;
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
        assert_eq!(rand_scalar.get_element(), rand_scalar2.get_element());
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
        assert_eq!(point_ab1.get_element(), point_ab2.get_element());
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
        let result = Ed25519Point::from_bytes(&test_vec);
        assert!(result.is_ok())
    }

    #[test]
    fn test_scalar_mul_multiply_by_1() {
        let g: GE = ECPoint::generator();
        let test_vec: [u8; 32];
        test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let tv_bn = BigInt::from(&test_vec[..]);
        let fe: FE = ECScalar::from(&tv_bn);
        let b_tag = &g * &fe;
        assert_eq!(b_tag.get_element(), g.get_element());
    }

}
