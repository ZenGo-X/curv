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
use std::str;
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
use arithmetic::traits::Modulo;

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
    // we chose to multiply by 8 all group elements to work in the prime order sub group.
    // each random fe is having its 3 first bits zeroed
    fn new_random() -> Ed25519Scalar {
        let mut scalar_bytes = [0u8; 32];
        let rng = &mut thread_rng();
        rng.fill(&mut scalar_bytes);
        let rnd_bn = BigInt::from(&scalar_bytes[..]);
        let rnd_bn_mod_q = BigInt::mod_mul(&rnd_bn, &BigInt::from(8), &FE::q());
        ECScalar::from(&rnd_bn_mod_q)
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
        //  let n_mod_q = n.modulus(&FE::q());
        let mut v = BigInt::to_vec(&n);
        let mut bytes_array_32: [u8; 32];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        bytes_array_32 = [0; SECRET_KEY_SIZE];
        let bytes = &v[..SECRET_KEY_SIZE];
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
        let other_point = Ed25519Scalar {
            purpose: "other add",
            fe: other.clone(),
        };
        let lhs_bn = self.to_big_int();
        let rhs_bn = other_point.to_big_int();
        let sum = BigInt::mod_add(&lhs_bn, &rhs_bn, &FE::q());
        let sum_fe: FE = ECScalar::from(&sum);

        sum_fe
    }

    fn mul(&self, other: &SK) -> Ed25519Scalar {
        let other_point = Ed25519Scalar {
            purpose: "other mul",
            fe: other.clone(),
        };
        let lhs_bn = self.to_big_int();
        let rhs_bn = other_point.to_big_int();
        let mul = BigInt::mod_mul(&lhs_bn, &rhs_bn, &FE::q());
        let mul_fe: FE = ECScalar::from(&mul);
        mul_fe
    }

    fn sub(&self, other: &SK) -> Ed25519Scalar {
        let other_point = Ed25519Scalar {
            purpose: "other sub",
            fe: other.clone(),
        };
        let lhs_bn = self.to_big_int();
        let rhs_bn = other_point.to_big_int();
        let sub = BigInt::mod_sub(&lhs_bn, &rhs_bn, &FE::q());
        let sub_fe: FE = ECScalar::from(&sub);
        sub_fe
    }

    fn invert(&self) -> Ed25519Scalar {
        let self_bn = self.to_big_int();
        let inv = self_bn.invert(&FE::q()).unwrap();
        let inv_fe: FE = ECScalar::from(&inv);
        inv_fe
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

impl PartialEq for Ed25519Scalar {
    fn eq(&self, other: &Ed25519Scalar) -> bool {
        self.get_element().to_bytes() == other.get_element().to_bytes()
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

impl PartialEq for Ed25519Point {
    fn eq(&self, other: &Ed25519Point) -> bool {
        self.get_element().to_bytes() == other.get_element().to_bytes()
    }
}

impl Ed25519Point {
    pub fn base_point2() -> Ed25519Point {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&vec![&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&vec![&hash]);
        let bytes = BigInt::to_vec(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        let eight = BigInt::from(8);
        let eight_fe: FE = ECScalar::from(&eight);
        let h = h * eight_fe;
        Ed25519Point {
            purpose: "random",
            ge: h.get_element(),
        }
    }
}
impl ECPoint<PK, SK> for Ed25519Point {
    fn generator() -> Ed25519Point {
        let vec_1: [u8; 32];
        vec_1 = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        Ed25519Point {
            purpose: "base_fe",
            ge: ge_scalarmult_base(&vec_1[..]),
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn x_coor(&self) -> Option<BigInt> {
        let y = self.y_coor().unwrap();
        Some(xrecover(y))
    }

    fn y_coor(&self) -> Option<BigInt> {
        let y_fe = SK::from_bytes(self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref());
        let y = Ed25519Scalar {
            purpose: "base_fe",
            fe: y_fe,
        };
        Some(y.to_big_int())
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from(self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref())
    }

    // from_bytes will return Ok only if the bytes encode a valid point.
    // since valid point are not necessarily in the sub group of prime order this needs to be checked
    // as well such that Ok will be returned only for valid point of the sub group prime order.
    // currently we change the encoded point by multiply by 8 to make sure it is in the sub group of prime order.
    // This is because for our use cases so far it doesn't matter and multiply by 8 is faster than testing for a point
    // in the sub group prime order
    fn from_bytes(bytes: &[u8]) -> Result<Ed25519Point, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_32 = [0u8; 32];
        let byte_len = bytes_vec.len();
        match byte_len {
            0...32 => {
                let mut template = vec![0; 32 - byte_len];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let ge_from_bytes = PK::from_bytes_negate_vartime(&bytes_array_32);
                match ge_from_bytes {
                    Some(_x) => {
                        let ge_bytes = ge_from_bytes.unwrap().to_bytes();
                        let ge_from_bytes = PK::from_bytes_negate_vartime(&ge_bytes[..]);
                        match ge_from_bytes {
                            Some(y) => {
                                let eight: FE = ECScalar::from(&BigInt::from(8));
                                let new_point = Ed25519Point {
                                    purpose: "random",
                                    ge: y,
                                };
                                Ok(new_point * eight)
                            }
                            None => Err(InvalidPublicKey),
                        }
                    }
                    None => Err(InvalidPublicKey),
                }
            }
            _ => {
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let ge_from_bytes = PK::from_bytes_negate_vartime(bytes);
                match ge_from_bytes {
                    Some(_x) => {
                        let ge_bytes = ge_from_bytes.unwrap().to_bytes();
                        let ge_from_bytes = PK::from_bytes_negate_vartime(&ge_bytes[..]);
                        match ge_from_bytes {
                            Some(y) => {
                                let eight: FE = ECScalar::from(&BigInt::from(8));
                                let new_point = Ed25519Point {
                                    purpose: "random",
                                    ge: y,
                                };
                                Ok(new_point * eight)
                            }
                            None => Err(InvalidPublicKey),
                        }
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

    fn scalar_mul(&self, fe: &SK) -> Ed25519Point {
        let vec_0: [u8; 32];
        vec_0 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let p2_point =
            GeP2::double_scalarmult_vartime(&fe.to_bytes()[..], self.get_element(), &vec_0[..]);
        let mut p2_bytes = p2_point.to_bytes();

        p2_bytes[31] ^= 1 << 7;

        let ge = GeP3::from_bytes_negate_vartime(&p2_bytes[..]).unwrap();

        Ed25519Point {
            purpose: "scalar_point_mul",
            ge,
        }
    }

    fn add_point(&self, other: &PK) -> Ed25519Point {
        let pkpk = self.ge.clone() + other.to_cached();
        let mut pk_p2_bytes = pkpk.to_p2().to_bytes();
        pk_p2_bytes[31] ^= 1 << 7;
        Ed25519Point {
            purpose: "combine",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Ed25519Point {
        let pkpk = self.ge.clone() - other.to_cached();
        let mut pk_p2_bytes = pkpk.to_p2().to_bytes();
        pk_p2_bytes[31] ^= 1 << 7;

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
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from(&bytes[..]);
        let mut state = serializer.serialize_struct("ed25519CurvePoint", 1)?;
        state.serialize_field("bytes_str", &bytes_as_bn.to_hex())?;
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
        formatter.write_str("ed25519CurvPoint")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Ed25519Point, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key.as_ref() {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => panic!("deSerialization failed!"),
            }
        }
        let bytes_bn = BigInt::from_hex(&bytes_str);
        let bytes = BigInt::to_vec(&bytes_bn);
        // println!("bytes des {:?}", bytes.clone());
        Ok(Ed25519Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }
}

//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
pub fn xrecover(y_coor: BigInt) -> BigInt {
    //   let d = "37095705934669439343138083508754565189542113879843219016388785533085940283555";
    //   let d_bn = BigInt::from(d.as_bytes());
    let q = BigInt::from(2u32).pow(255u32) - BigInt::from(19u32);
    let one = BigInt::one();
    let d_n = -BigInt::from(121665i32);
    let d_d = expmod(&BigInt::from(121666), &(q.clone() - BigInt::from(2)), &q);

    let d_bn = d_n * d_d;
    let y_sqr = y_coor.clone() * y_coor.clone();
    let u = y_sqr.clone() - one.clone();
    let v = y_sqr * d_bn.clone() + one.clone();
    let v_inv = expmod(&v, &(q.clone() - BigInt::from(2)), &q);

    let x_sqr = u * v_inv;
    let q_plus_3_div_8 = (q.clone() + BigInt::from(3i32)) / BigInt::from(8i32);

    let mut x = expmod(&x_sqr, &q_plus_3_div_8, &q);
    if BigInt::mod_sub(&(x.clone() * x.clone()), &x_sqr, &q) != BigInt::zero() {
        let q_minus_1_div_4 = (q.clone() - BigInt::from(3i32)) / BigInt::from(4i32);
        let i = expmod(&BigInt::from(2i32), &q_minus_1_div_4, &q);
        x = BigInt::mod_mul(&x, &i, &q);
    }
    if x.modulus(&BigInt::from(2i32)) != BigInt::zero() {
        x = q.clone() - x.clone();
    }

    x
}

//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
pub fn expmod(b: &BigInt, e: &BigInt, m: &BigInt) -> BigInt {
    let one = BigInt::one();
    if e.clone() == BigInt::zero() {
        return one.clone();
    };
    let t_temp = expmod(b, &(e.clone() / BigInt::from(2u32)), m);
    let mut t = BigInt::mod_pow(&t_temp, &BigInt::from(2u32), m);

    if e.clone().modulus(&BigInt::from(2)) != BigInt::zero() {
        t = BigInt::mod_mul(&t, b, m);
    }
    return t;
}

#[cfg(feature = "ed25519")]
#[cfg(test)]
mod tests {
    use super::Ed25519Point;
    use arithmetic::traits::Modulo;
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use serde_json;
    use BigInt;
    use {FE, GE};

    #[test]
    fn test_serdes_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(des_pk, pk * &eight);

        let pk = GE::base_point2();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(des_pk, pk * &eight);
    }

    #[test]
    #[should_panic]
    fn test_serdes_bad_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        let s: String = s.replace("5866", "5867");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(des_pk, pk * &eight);
    }

    #[test]
    fn test_from_mpz() {
        let rand_scalar: FE = ECScalar::new_random();
        let rand_bn = rand_scalar.to_big_int();
        let rand_scalar2: FE = ECScalar::from(&rand_bn);
        assert_eq!(rand_scalar, rand_scalar2);
    }

    #[test]
    fn test_minus_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_minus_b_fe: FE = a.sub(&b.get_element());
        let base: GE = ECPoint::generator();
        let point_ab1 = &base * &a_minus_b_fe;
        let point_a = &base * &a;
        let point_b = &base * &b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_plus_b_fe = a.clone() + &b;
        let base: GE = ECPoint::generator();
        let point_ab1 = &base * &a_plus_b_fe;
        let point_a = &base * &a;
        let point_b = &base * &b;
        let point_ab2 = point_a.add_point(&point_b.get_element());

        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_scalar() {
        let a: FE = ECScalar::new_random();
        let zero: FE = FE::zero();
        let a_plus_zero: FE = a.clone() + zero;

        assert_eq!(a_plus_zero, a);
    }

    #[test]
    fn test_mul_scalar() {
        let a = [
            10, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 10, 10, 10,
        ];
        let a_bn = BigInt::from(&a[..]);
        let a_fe: FE = ECScalar::from(&a_bn);

        let five = BigInt::from(5);
        let five_fe: FE = ECScalar::from(&five);
        let five_a_bn = BigInt::mod_mul(&a_bn, &five, &FE::q());
        let five_a_fe = five_fe * a_fe;
        let five_a_fe_2: FE = ECScalar::from(&five_a_bn);

        assert_eq!(five_a_fe, five_a_fe_2);
    }

    #[test]
    fn test_mul_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_mul_b_fe = a.clone() * &b;
        let base: GE = ECPoint::generator();
        let point_ab1 = &base * &a_mul_b_fe;
        let point_a = &base * &a;
        let point_ab2 = point_a.scalar_mul(&b.get_element());

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
    fn test_from_bytes_2() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
            6,
        ];
        let result = Ed25519Point::from_bytes(&test_vec);
        assert!(result.is_ok())
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

        let fe: FE = ECScalar::from(&BigInt::from(1));
        let b_tag = &g * &fe;
        assert_eq!(b_tag, g);
    }

    #[test]
    fn test_gep3_to_bytes_from_bytes() {
        let g: GE = ECPoint::generator();
        let test_vec: [u8; 32];
        test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let tv_bn = BigInt::from(&test_vec[..]);
        let test_fe: FE = ECScalar::from(&tv_bn);
        let test_ge = g * &test_fe;
        let test_ge_bytes = test_ge.get_element().to_bytes();
        let test_ge2: GE = ECPoint::from_bytes(&test_ge_bytes[..]).unwrap();
        let eight: FE = ECScalar::from(&BigInt::from(8));

        assert_eq!(test_ge2, test_ge * eight);
    }

    #[test]
    fn test_scalar_to_bn_and_back() {
        let s_a: FE = ECScalar::new_random();
        let s_bn = s_a.to_big_int();
        let s_b: FE = ECScalar::from(&s_bn);
        assert_eq!(s_a, s_b);
    }
    #[test]
    fn test_xy_coor() {
        let g: GE = GE::generator();
        assert_eq!(
            g.x_coor().unwrap().to_str_radix(10),
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"
        );
    }

}
