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

//https://cr.yp.to/ecdh.html -> https://cr.yp.to/ecdh/curve25519-20060209.pdf
use BigInt;
use serde::de;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use arithmetic::traits::Converter;
use std::fmt;
use super::curve25519_dalek::constants::BASEPOINT_ORDER;
use super::curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use super::curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use super::curve25519_dalek::scalar::Scalar;
use super::rand::{thread_rng,Rng};
use std::ops::{Add, Mul};
use super::traits::{ECPoint, ECScalar};
pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;
use merkle::Hashable;
use ring::digest::Context;
pub type SK = Scalar;
pub type PK = CompressedRistretto;

#[derive(Clone, PartialEq, Debug)]
pub struct Curve25519Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, PartialEq, Debug)]
pub struct Curve25519Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Curve25519Point;
pub type FE = Curve25519Scalar;

impl ECScalar<SK> for Curve25519Scalar {
    fn new_random() -> Curve25519Scalar {
        Curve25519Scalar {
            purpose: "random",
            fe: SK::random(&mut thread_rng()),
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }
    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Curve25519Scalar {
        let mut v = BigInt::to_vec(n);
        //TODO: add consistency check for sizes max 32/ max 64
        let mut bytes_array_32: [u8; 32];
        let mut bytes_array_64: [u8; 64];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() > SECRET_KEY_SIZE && v.len() < 2*SECRET_KEY_SIZE{
            let mut template = vec![0; 2*SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() == SECRET_KEY_SIZE {
            bytes_array_32 = [0; SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_32.copy_from_slice(&bytes);
            bytes_array_32.reverse();
             Curve25519Scalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order(bytes_array_32),
            }
        }

        else {
            bytes_array_64 = [0; 2 * SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_64.copy_from_slice(&bytes);
            bytes_array_64.reverse();
           Curve25519Scalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order_wide(&bytes_array_64),
            }
        }

    }


    fn to_big_int(&self) -> BigInt {
        let t1 = &self.fe.to_bytes()[0..self.fe.to_bytes().len()];
        let mut t2  = t1.to_vec();
        t2.reverse();
        BigInt::from(&t2[0..self.fe.to_bytes().len()])
    }

    fn q(&self) -> BigInt {
        BigInt::from(BASEPOINT_ORDER.to_bytes()[0..BASEPOINT_ORDER.to_bytes().len()].as_ref())
    }

    fn add(&self, other: &SK) -> Curve25519Scalar {
        Curve25519Scalar {
            purpose: "add",
            fe: &self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> Curve25519Scalar {
        Curve25519Scalar {
            purpose: "mul",
            fe: &self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> Curve25519Scalar {
        Curve25519Scalar {
            purpose: "sub",
            fe: &self.get_element() - other,
        }
    }
}

impl Serialize for Curve25519Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Curve25519Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Curve25519Scalar, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Curve25519Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Curve25519Scalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}


impl ECPoint<PK, SK> for Curve25519Point {
    fn generator() -> Curve25519Point {
        Curve25519Point {
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
    fn from(bytes: &[u8]) -> Curve25519Point{
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_64 =  [0u8; 64];

        if bytes_vec.len() < 64 {
            let mut template = vec![0; 64 - bytes_vec.len()];
            template.extend_from_slice(&bytes);
            let bytes_vec = template;
        }
        let bytes_slice = &bytes_vec[..];
        bytes_array_64.copy_from_slice(&bytes_slice);
        let r_point = RistrettoPoint::from_uniform_bytes(&bytes_array_64);
        let r_point_compress = r_point.compress();
        Curve25519Point{
            purpose: "random bytes",
            ge: r_point_compress,
        }


    }


    fn pk_to_key_slice(&self) -> Vec<u8> {
        let result = self.ge.to_bytes();
        result.to_vec()
    }

    fn scalar_mul(self, fe: &SK) -> Curve25519Point {
        let skpk = fe * (self.ge.decompress().unwrap());
        Curve25519Point {
            purpose: "scalar_point_mul",
            ge: skpk.compress(),
        }
    }

    fn add_point(&self, other: &PK) -> Curve25519Point {
        let pkpk = self.ge.decompress().unwrap() + other.decompress().unwrap();
        Curve25519Point {
            purpose: "combine",
            ge: pkpk.compress(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> Curve25519Point {
        unimplemented!();
    }
}

impl Mul<Curve25519Scalar> for Curve25519Point {
    type Output = Curve25519Point;
    fn mul(self, other: Curve25519Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Curve25519Scalar> for Curve25519Point {
    type Output = Curve25519Point;
    fn mul(self, other: &'o Curve25519Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Curve25519Point> for Curve25519Point {
    type Output = Curve25519Point;
    fn add(self, other: Curve25519Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Curve25519Point> for Curve25519Point {
    type Output = Curve25519Point;
    fn add(self, other: &'o Curve25519Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}


impl Hashable for Curve25519Point {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.update(&bytes);
    }
}

impl Serialize for Curve25519Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.x_coor().to_hex())?;
        state.serialize_field("y", &self.y_coor().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Curve25519Point {
    fn deserialize<D>(deserializer: D) -> Result<Curve25519Point, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_map(Secp256k1PointVisitor)
    }
}

struct Secp256k1PointVisitor;

impl<'de> Visitor<'de> for Secp256k1PointVisitor {
    type Value = Curve25519Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Point")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Curve25519Point, E::Error> {
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

        Ok(Curve25519Point::from_coor(&bx, &by))
    }
}
#[cfg(feature = "curve25519")]
#[cfg(test)]
mod tests {
    use super::ECScalar;
    use FE;
    use BigInt;
    use arithmetic::traits::Converter;

    #[test]
    fn test_from_mpz() {
        let rand_scalar: FE = ECScalar::new_random();
        let rand_bn = rand_scalar.to_big_int();
        let rand_scalar2: FE  = ECScalar::from(&rand_bn);
        assert_eq!(rand_scalar.get_element(), rand_scalar2.get_element());

    }
}
