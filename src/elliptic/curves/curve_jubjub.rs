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

// jubjub : https://z.cash/technology/jubjub/
use std::fmt::Debug;
use std::str;
pub const SECRET_KEY_SIZE: usize = 64;
use super::pairing::bls12_381::Bls12;
use super::sapling_crypto::jubjub::*;
use super::sapling_crypto::jubjub::{edwards, fs::Fs, JubjubBls12, PrimeOrder, Unknown};
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
pub type SK = Fs;
// we will take advantage of the fact that jubjub lib provides a uninque type for prime order sub group
pub type PK = edwards::Point<Bls12, PrimeOrder>; // specific type for element in the prime order sub group
pub type PKu = edwards::Point<Bls12, Unknown>; // special type for general point
use super::pairing::Field;
use super::pairing::PrimeField;
use super::pairing::PrimeFieldRepr;
use super::sapling_crypto::jubjub::JubjubParams;
use super::sapling_crypto::jubjub::ToUniform;
use arithmetic::traits::{Modulo, Samplable};
use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
pub struct JubjubScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone)]
pub struct JubjubPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = JubjubPoint;
pub type FE = JubjubScalar;

impl Zeroize for FE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar<SK> for JubjubScalar {
    // jujub library are zero masking the first 4 bits for all random numbers (in ed25519 we do it here)
    // currently they are using rand 0.4 which is outdated therefore we do it here ourselves.
    fn new_random() -> JubjubScalar {
        //   let mut arr = [0u8; 32];
        // thread_rng().fill(&mut arr[..]);
        //    JubjubScalar {
        //        purpose: "random",
        //        fe:SK::rand(&mut arr),
        //    }
        let rnd_bn = BigInt::sample_below(&FE::q());
        let rnd_bn_mul_8 = BigInt::mod_mul(&rnd_bn, &BigInt::from(8), &FE::q());
        ECScalar::from(&rnd_bn_mul_8)
    }

    fn zero() -> JubjubScalar {
        JubjubScalar {
            purpose: "zero",
            fe: SK::zero(),
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }
    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> JubjubScalar {
        let mut v = BigInt::to_vec(&n);
        let mut bytes_array: [u8; SECRET_KEY_SIZE];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        bytes_array = [0; SECRET_KEY_SIZE];
        let bytes = &v[..SECRET_KEY_SIZE];
        bytes_array.copy_from_slice(&bytes);

        bytes_array.reverse();

        JubjubScalar {
            purpose: "from_big_int",
            fe: SK::to_uniform(&bytes_array),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let to_fs_rep = self.fe.into_repr();
        let to_u64 = to_fs_rep.0.iter().rev();
        let to_bn = to_u64.fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    }

    fn q() -> BigInt {
        let q_u64: [u64; 4] = [
            0xd0970e5ed6f72cb7,
            0xa6682093ccc81082,
            0x6673b0101343b00,
            0xe7db4ea6533afa9,
        ];
        let to_bn = q_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    }

    fn add(&self, other: &SK) -> JubjubScalar {
        let mut add_fe = JubjubScalar {
            purpose: "other add",
            fe: *other,
        };
        add_fe.fe.add_assign(&self.fe);
        add_fe
    }

    fn mul(&self, other: &SK) -> JubjubScalar {
        let mut mul_fe = JubjubScalar {
            purpose: "other mul",
            fe: *other,
        };
        mul_fe.fe.mul_assign(&self.fe);
        mul_fe
    }

    fn sub(&self, other: &SK) -> JubjubScalar {
        let mut other_neg = other.clone();
        other_neg.negate();
        let sub_fe = JubjubScalar {
            purpose: "other sub",
            fe: other_neg.clone(),
        };
        self.add(&sub_fe.get_element())
    }

    fn invert(&self) -> JubjubScalar {
        let inv_sc = self.fe.inverse().unwrap();
        let inv_fe = JubjubScalar {
            purpose: "inverse",
            fe: inv_sc,
        };
        inv_fe
    }
}

impl Debug for JubjubScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose, self.fe,
        )
    }
}

impl PartialEq for JubjubScalar {
    fn eq(&self, other: &JubjubScalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Mul<JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;
    fn mul(self, other: JubjubScalar) -> JubjubScalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;
    fn mul(self, other: &'o JubjubScalar) -> JubjubScalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;
    fn add(self, other: JubjubScalar) -> JubjubScalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o JubjubScalar> for JubjubScalar {
    type Output = JubjubScalar;
    fn add(self, other: &'o JubjubScalar) -> JubjubScalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for JubjubScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for JubjubScalar {
    fn deserialize<D>(deserializer: D) -> Result<JubjubScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = JubjubScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("jubjub")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<JubjubScalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl Debug for JubjubPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.bytes_compressed_to_big_int().to_str_radix(16)
        )
    }
}

impl PartialEq for JubjubPoint {
    fn eq(&self, other: &JubjubPoint) -> bool {
        self.get_element() == other.get_element()
    }
}

impl JubjubPoint {
    pub fn base_point2() -> JubjubPoint {
        let g: GE = ECPoint::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&[&hash]);
        let hash = HSha256::create_hash(&[&hash]);
        let hash = HSha256::create_hash(&[&hash]);

        let bytes = BigInt::to_vec(&hash);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        JubjubPoint {
            purpose: "random",
            ge: h.get_element(),
        }
    }
}

impl Zeroize for GE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint<PK, SK> for JubjubPoint {
    fn generator() -> JubjubPoint {
        let params = JubjubBls12::new();
        let p_g = FixedGenerators::SpendingKeyGenerator;

        JubjubPoint {
            purpose: "base_fe",
            ge: PK::from(params.generator(p_g).clone()),
        }
    }

    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    fn x_coor(&self) -> Option<BigInt> {
        let x_coor = PK::into_xy(&self.ge).0.into_repr();
        let to_u64 = x_coor.0.iter().rev();
        let to_bn = to_u64.fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        Some(to_bn)
    }

    fn y_coor(&self) -> Option<BigInt> {
        let y_coor = PK::into_xy(&self.ge).1.into_repr();
        let to_u64 = y_coor.0.iter().rev();
        let to_bn = to_u64.fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        Some(to_bn)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let (x, _) = self.ge.into_xy();
        let sign = x.into_repr().is_odd();
        let y_coor = self.y_coor().unwrap();
        let point_compressed_bn = (BigInt::from(sign as u32) << 255) + y_coor;
        point_compressed_bn
    }

    fn from_bytes(bytes: &[u8]) -> Result<JubjubPoint, ErrorKey> {
        let params = &JubjubBls12::new();
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
                println!("bytes_array_32_u: {:?}", bytes_array_32);
                let ge_from_bytes = PKu::read(&bytes_array_32[..], params);
                match ge_from_bytes {
                    Ok(x) => {
                        let new_point = JubjubPoint {
                            purpose: "random",
                            ge: x.mul_by_cofactor(params),
                        };
                        Ok(new_point)
                    }

                    Err(e) => {
                        println!("ERROR: {:?}", e);
                        Err(InvalidPublicKey)
                    }
                }
            }
            _ => {
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                println!("bytes_array_32_d: {:?}", bytes_array_32);
                let ge_from_bytes = PKu::read(&bytes_array_32[..], params);
                match ge_from_bytes {
                    Ok(x) => {
                        let new_point = JubjubPoint {
                            purpose: "random",
                            ge: x.mul_by_cofactor(params),
                        };
                        Ok(new_point)
                    }

                    Err(_) => Err(InvalidPublicKey),
                }
            }
        }
    }

    // in this case the opposite of from_bytes: takes compressed pk to 32 bytes.
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut v = vec![];
        self.ge.write(&mut v).unwrap();
        v
        //    let point_compressed_bn = self.bytes_compressed_to_big_int();
        //    BigInt::to_vec(&point_compressed_bn)
    }

    fn scalar_mul(&self, fe: &SK) -> JubjubPoint {
        let params = &JubjubBls12::new();
        let ge = self.ge.mul(fe.clone(), params);
        JubjubPoint {
            purpose: "scalar_point_mul",
            ge,
        }
    }

    fn add_point(&self, other: &PK) -> JubjubPoint {
        let params = &JubjubBls12::new();
        let ge = self.ge.add(other, params);
        JubjubPoint {
            purpose: "combine",
            ge,
        }
    }

    fn sub_point(&self, other: &PK) -> JubjubPoint {
        let params = &JubjubBls12::new();
        let other_neg = other.negate();
        let ge = self.ge.add(&other_neg, params);

        JubjubPoint { purpose: "sub", ge }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> JubjubPoint {
        // TODO
        unimplemented!();
    }
}

impl Mul<JubjubScalar> for JubjubPoint {
    type Output = JubjubPoint;
    fn mul(self, other: JubjubScalar) -> JubjubPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o JubjubScalar> for JubjubPoint {
    type Output = JubjubPoint;
    fn mul(self, other: &'o JubjubScalar) -> JubjubPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o JubjubScalar> for &'o JubjubPoint {
    type Output = JubjubPoint;
    fn mul(self, other: &'o JubjubScalar) -> JubjubPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<JubjubPoint> for JubjubPoint {
    type Output = JubjubPoint;
    fn add(self, other: JubjubPoint) -> JubjubPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o JubjubPoint> for JubjubPoint {
    type Output = JubjubPoint;
    fn add(self, other: &'o JubjubPoint) -> JubjubPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o JubjubPoint> for &'o JubjubPoint {
    type Output = JubjubPoint;
    fn add(self, other: &'o JubjubPoint) -> JubjubPoint {
        self.add_point(&other.get_element())
    }
}

impl Hashable for JubjubPoint {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.update(&bytes);
    }
}

impl Serialize for JubjubPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from(&bytes[..]);
        let mut state = serializer.serialize_struct("JubjubCurvePoint", 1)?;
        state.serialize_field("bytes_str", &bytes_as_bn.to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for JubjubPoint {
    fn deserialize<D>(deserializer: D) -> Result<JubjubPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RistrettoCurvPointVisitor)
    }
}

struct RistrettoCurvPointVisitor;

impl<'de> Visitor<'de> for RistrettoCurvPointVisitor {
    type Value = JubjubPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("JubjubCurvePoint")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<JubjubPoint, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => panic!("deSerialization failed!"),
            }
        }
        let bytes_bn = BigInt::from_hex(&bytes_str);
        let bytes = BigInt::to_vec(&bytes_bn);
        println!("bytes: {:?}", bytes);

        Ok(JubjubPoint::from_bytes(&bytes[..]).expect("error deserializing point"))
    }
}

#[cfg(feature = "curvejubjub")]
#[cfg(test)]
mod tests {
    use super::JubjubPoint;
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
        let s: String = s.replace("30", "20");
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5,
            6,
        ];
        let result = JubjubPoint::from_bytes(&test_vec);
        assert!(result.is_ok())
    }
    #[test]
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = JubjubPoint::from_bytes(&test_vec);
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
    fn test_scalar_to_bn_and_back() {
        let s_a: FE = ECScalar::new_random();
        let s_bn = s_a.to_big_int();
        let s_b: FE = ECScalar::from(&s_bn);
        assert_eq!(s_a, s_b);
    }

}
