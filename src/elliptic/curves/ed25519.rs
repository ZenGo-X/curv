/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// paper: https://ed25519.cr.yp.to/ed25519-20110926.pdf
// based on https://docs.rs/cryptoxide/0.1.0/cryptoxide/curve25519/index.html
// https://cr.yp.to/ecdh/curve25519-20060209.pdf
use std::fmt::Debug;
use std::str;
pub const TWO_TIMES_SECRET_KEY_SIZE: usize = 64;
use super::traits::{ECPoint, ECScalar};
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
pub type SK = Fe;
pub type PK = GeP3;
use crate::arithmetic::traits::*;
use crate::BigInt;
use crate::ErrorKey::{self, InvalidPublicKey};
#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
use cryptoxide::curve25519::*;
#[cfg(feature = "merkle")]
use merkle::Hashable;
use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
pub struct Ed25519Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Copy)]
pub struct Ed25519Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Ed25519Point;
pub type FE = Ed25519Scalar;

impl Zeroize for Ed25519Scalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
impl ECScalar for Ed25519Scalar {
    type SecretKey = SK;

    // we chose to multiply by 8 (co-factor) all group elements to work in the prime order sub group.
    // each random fe is having its 3 first bits zeroed
    fn new_random() -> Ed25519Scalar {
        let rnd_bn = BigInt::sample_below(&FE::q());
        let rnd_bn_mul_8 = BigInt::mod_mul(&rnd_bn, &BigInt::from(8), &FE::q());
        ECScalar::from(&rnd_bn_mul_8)
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
        let mut v = BigInt::to_vec(&n);
        if v.len() > TWO_TIMES_SECRET_KEY_SIZE {
            v = v[0..TWO_TIMES_SECRET_KEY_SIZE].to_vec();
        }

        let mut template = vec![0; TWO_TIMES_SECRET_KEY_SIZE - v.len()];
        template.extend_from_slice(&v);
        v = template;
        v.reverse();
        sc_reduce(&mut v[..]);
        Ed25519Scalar {
            purpose: "from_big_int",
            fe: SK::from_bytes(&v[..]),
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
            fe: *other,
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
            fe: *other,
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
            fe: *other,
        };
        let lhs_bn = self.to_big_int();
        let rhs_bn = other_point.to_big_int();
        let sub = BigInt::mod_sub(&lhs_bn, &rhs_bn, &FE::q());
        let sub_fe: FE = ECScalar::from(&sub);
        sub_fe
    }

    fn invert(&self) -> Ed25519Scalar {
        let self_bn = self.to_big_int();
        let inv = BigInt::mod_inv(&self_bn, &FE::q()).unwrap();
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
        deserializer.deserialize_str(Ed25519ScalarVisitor)
    }
}

struct Ed25519ScalarVisitor;

impl<'de> Visitor<'de> for Ed25519ScalarVisitor {
    type Value = Ed25519Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("ed25519")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Ed25519Scalar, E> {
        let v = BigInt::from_hex(s).map_err(E::custom)?;
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

impl Zeroize for Ed25519Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for Ed25519Point {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = Ed25519Scalar;

    fn base_point2() -> Ed25519Point {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&[&hash]);
        let bytes = BigInt::to_vec(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        Ed25519Point {
            purpose: "random",
            ge: h.get_element(),
        }
    }

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
            0..=32 => {
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
        let pkpk = self.ge + other.to_cached();
        let mut pk_p2_bytes = pkpk.to_p2().to_bytes();
        pk_p2_bytes[31] ^= 1 << 7;
        Ed25519Point {
            purpose: "combine",
            ge: PK::from_bytes_negate_vartime(&pk_p2_bytes).unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Ed25519Point {
        let pkpk = self.ge - other.to_cached();
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

#[cfg(feature = "merkle")]
impl Hashable for Ed25519Point {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Serialize for Ed25519Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from(&bytes[..]);
        let padded_bytes_hex = format!("{:0>64}", bytes_as_bn.to_hex());
        let mut state = serializer.serialize_struct("ed25519CurvePoint", 1)?;
        state.serialize_field("bytes_str", &padded_bytes_hex)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Ed25519Point {
    fn deserialize<D>(deserializer: D) -> Result<Ed25519Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = &["bytes_str"];
        deserializer.deserialize_struct("Ed25519Point", fields, Ed25519PointVisitor)
    }
}

struct Ed25519PointVisitor;

impl<'de> Visitor<'de> for Ed25519PointVisitor {
    type Value = Ed25519Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Ed25519Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Ed25519Point, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes_str = seq
            .next_element()?
            .ok_or(V::Error::invalid_length(0, &"a single element"))?;
        let bytes_bn = BigInt::from_hex(bytes_str).map_err(V::Error::custom)?;
        let bytes = BigInt::to_vec(&bytes_bn);
        Ok(Ed25519Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Ed25519Point, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => return Err(E::Error::unknown_field(key, &["bytes_str"]))?,
            }
        }

        let bytes_bn = BigInt::from_hex(&bytes_str).map_err(E::Error::custom)?;
        let bytes = BigInt::to_vec(&bytes_bn);

        Ed25519Point::from_bytes(&bytes[..]).map_err(|_| E::Error::custom("invalid ed25519 point"))
    }
}

#[allow(clippy::many_single_char_names)]
//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
pub fn xrecover(y_coor: BigInt) -> BigInt {
    //   let d = "37095705934669439343138083508754565189542113879843219016388785533085940283555";
    //   let d_bn = BigInt::from(d.as_bytes());
    let q = BigInt::from(2u32).pow(255u32) - BigInt::from(19u32);
    let one = BigInt::one();
    let d_n = -BigInt::from(121_665i32);
    let d_d = expmod(&BigInt::from(121_666), &(q.clone() - BigInt::from(2)), &q);

    let d_bn = d_n * d_d;
    let y_sqr = y_coor.clone() * y_coor;
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
pub fn expmod(b: &BigInt, e: &BigInt, m: &BigInt) -> BigInt {
    let one = BigInt::one();
    if e.clone() == BigInt::zero() {
        return one;
    };
    let t_temp = expmod(b, &(e.clone() / BigInt::from(2u32)), m);
    let mut t = BigInt::mod_pow(&t_temp, &BigInt::from(2u32), m);

    if BigInt::modulus(&e, &BigInt::from(2)) != BigInt::zero() {
        t = BigInt::mod_mul(&t, b, m);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Point, Ed25519Scalar};
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;

    type GE = Ed25519Point;
    type FE = Ed25519Scalar;

    #[test]
    #[allow(clippy::op_ref)] // Enables type inference.
    fn test_serdes_pk() {
        let mut pk = GE::generator();
        let mut s = serde_json::to_string(&pk).expect("Failed in serialization");
        let mut des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(des_pk, pk * &eight);

        pk = GE::base_point2();
        s = serde_json::to_string(&pk).expect("Failed in serialization");
        des_pk = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk * &eight);

        // deserialize serialization of bytes_str < 64 hex
        s = "{\"bytes_str\":\"2c42d43e1a277e8f3d7d5aacde519c80b913341e425b624d867f790d1578e0\"}"
            .to_string();
        des_pk = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight_inverse: FE = eight.invert();
        let des_pk_mul = des_pk * &eight_inverse;
        assert_eq!(
            des_pk_mul.bytes_compressed_to_big_int().to_hex(),
            "2c42d43e1a277e8f3d7d5aacde519c80b913341e425b624d867f790d1578e0"
        );

        // serialize with padding
        let ser_pk = serde_json::to_string(&des_pk_mul).expect("Failed in serialization");
        assert_eq!(
            &ser_pk,
            "{\"bytes_str\":\"002c42d43e1a277e8f3d7d5aacde519c80b913341e425b624d867f790d1578e0\"}"
        );

        // deserialize a padded serialization
        let des_pk2: GE = serde_json::from_str(&ser_pk).expect("Failed in deserialization");
        assert_eq!(des_pk_mul, des_pk2 * &eight_inverse);
    }

    #[test]
    #[allow(clippy::op_ref)] // Enables type inference.
    fn bincode_pk() {
        let pk = GE::generator();
        let encoded = bincode::serialize(&pk).unwrap();
        let decoded: Ed25519Point = bincode::deserialize(encoded.as_slice()).unwrap();
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(pk * &eight, decoded);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::op_ref)] // Enables type inference.
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
        let point_ab1 = base * a_minus_b_fe;
        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_plus_b_fe = a + b;
        let base: GE = ECPoint::generator();
        let point_ab1 = base * a_plus_b_fe;
        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.add_point(&point_b.get_element());

        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_scalar() {
        let a: FE = ECScalar::new_random();
        let zero: FE = FE::zero();
        let a_plus_zero: FE = a + zero;

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
        let a_mul_b_fe = a * b;
        let base: GE = ECPoint::generator();
        let point_ab1 = base * a_mul_b_fe;
        let point_a = base * a;
        let point_ab2 = point_a.scalar_mul(&b.get_element());

        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_invert() {
        let a: FE = ECScalar::new_random();

        let a_bn = a.to_big_int();

        let a_inv = a.invert();
        let a_inv_bn_1 = BigInt::mod_inv(&a_bn, &FE::q()).unwrap();
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
        let b_tag = g * fe;
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
        let test_ge = g * test_fe;
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
            g.x_coor().unwrap().to_hex(),
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"
        );
    }
}
