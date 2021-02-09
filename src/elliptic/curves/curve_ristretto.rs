#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use super::traits::{ECPoint, ECScalar};
use crate::arithmetic::traits::*;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::BigInt;
use crate::ErrorKey::{self, InvalidPublicKey};
use curve25519_dalek::constants::BASEPOINT_ORDER;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use std::str;
pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;

use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
#[cfg(feature = "merkle")]
use merkle::Hashable;

pub type SK = Scalar;
pub type PK = CompressedRistretto;

#[derive(Clone, Debug, Copy)]
pub struct RistrettoScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug, Copy)]
pub struct RistrettoCurvPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = RistrettoCurvPoint;
pub type FE = RistrettoScalar;

impl Zeroize for RistrettoScalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar for RistrettoScalar {
    type SecretKey = SK;

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
        let (_sign, mut v) = BigInt::to_bytes(n);
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
        BigInt::from_bytes(Sign::Positive, &t2[0..self.fe.to_bytes().len()])
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
            fe: self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "mul",
            fe: self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "sub",
            fe: self.get_element() - other,
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
        formatter.write_str("ristretto")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<RistrettoScalar, E> {
        let v = BigInt::from_hex(s).map_err(E::custom)?;
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

impl Zeroize for RistrettoCurvPoint {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for RistrettoCurvPoint {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = RistrettoScalar;

    fn base_point2() -> RistrettoCurvPoint {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let (_sign, bytes) = BigInt::to_bytes(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        RistrettoCurvPoint {
            purpose: "random",
            ge: h.get_element(),
        }
    }

    fn generator() -> RistrettoCurvPoint {
        RistrettoCurvPoint {
            purpose: "base_fe",
            ge: RISTRETTO_BASEPOINT_COMPRESSED,
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn x_coor(&self) -> Option<BigInt> {
        unimplemented!();
    }

    fn y_coor(&self) -> Option<BigInt> {
        let y_fe = SK::from_bytes_mod_order(self.ge.to_bytes());
        let y_fe = RistrettoScalar {
            purpose: "y_coor",
            fe: y_fe,
        };
        Some(y_fe.to_big_int())
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from_bytes(
            Sign::Positive,
            self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref(),
        )
    }
    fn from_bytes(bytes: &[u8]) -> Result<RistrettoCurvPoint, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_32 = [0u8; 32];
        let byte_len = bytes_vec.len();
        match byte_len {
            0..=32 => {
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

#[cfg(feature = "merkle")]
impl Hashable for RistrettoCurvPoint {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Serialize for RistrettoCurvPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from_bytes(Sign::Positive, &bytes[..]);
        let mut state = serializer.serialize_struct("RistrettoCurvPoint", 1)?;
        state.serialize_field("bytes_str", &bytes_as_bn.to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RistrettoCurvPoint {
    fn deserialize<D>(deserializer: D) -> Result<RistrettoCurvPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["bytes_str"];
        deserializer.deserialize_struct("RistrettoCurvPoint", FIELDS, RistrettoCurvPointVisitor)
    }
}

struct RistrettoCurvPointVisitor;

impl<'de> Visitor<'de> for RistrettoCurvPointVisitor {
    type Value = RistrettoCurvPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("RistrettoCurvPoint")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<RistrettoCurvPoint, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes_str = seq
            .next_element()?
            .ok_or(V::Error::invalid_length(0, &"a single element"))?;
        let bytes_bn = BigInt::from_hex(bytes_str).map_err(V::Error::custom)?;
        let (_sign, bytes) = BigInt::to_bytes(&bytes_bn);
        RistrettoCurvPoint::from_bytes(&bytes[..])
            .map_err(|_| V::Error::custom("failed to parse ristretto point"))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<RistrettoCurvPoint, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => return Err(E::Error::unknown_field(key, &["bytes_str"])),
            }
        }
        let bytes_bn = BigInt::from_hex(&bytes_str).map_err(E::Error::custom)?;
        let (_sign, bytes) = BigInt::to_bytes(&bytes_bn);

        RistrettoCurvPoint::from_bytes(&bytes[..])
            .map_err(|_| E::Error::custom("failed to parse ristretto point"))
    }
}

#[cfg(test)]
mod tests {
    use super::{RistrettoCurvPoint, RistrettoScalar};
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;
    use serde_json;

    type GE = RistrettoCurvPoint;
    type FE = RistrettoScalar;

    #[test]
    fn test_serdes_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);

        let pk = GE::base_point2();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

    #[test]
    fn bincode_pk() {
        let pk = GE::generator();
        let encoded = bincode::serialize(&pk).unwrap();
        let decoded: RistrettoCurvPoint = bincode::deserialize(encoded.as_slice()).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    #[should_panic]
    fn test_serdes_bad_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        let s: String = s.replace("e2f2", "e2f5");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

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
        let (_sign, point_bytes) = BigInt::to_bytes(&point_bn);
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
        let point_ab1 = base * a_minus_b_fe;
        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
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
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = RistrettoCurvPoint::from_bytes(&test_vec);
        assert!(result.is_ok())
    }
}
