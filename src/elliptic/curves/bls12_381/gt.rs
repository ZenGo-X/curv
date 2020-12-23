/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::fmt::Debug;
use std::str;
pub const SECRET_KEY_SIZE: usize = 32;
use super::super::traits::ECScalar;
use crate::arithmetic::traits::Converter;

use bls12_381::Gt;
use bls12_381::Scalar;
use serde::de;
use serde::de::Visitor;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
pub type SK = Scalar;
pub type PK = Gt;
use crate::elliptic::curves::bls12_381::g1::GE as G1;
use crate::elliptic::curves::bls12_381::g2::GE as G2;

use crate::arithmetic::traits::Samplable;
use crate::BigInt;

use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

use crate::elliptic::curves::traits::ECPoint;
use bls12_381::pairing;
#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
#[cfg(feature = "merkle")]
use merkle::Hashable;

#[derive(Clone, Copy)]
pub struct FieldScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct GtPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = GtPoint;
pub type FE = FieldScalar;

impl Zeroize for FieldScalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar for FieldScalar {
    type SecretKey = SK;
    fn new_random() -> FieldScalar {
        let rnd_bn = BigInt::sample_below(&FE::q());
        ECScalar::from(&rnd_bn)
    }

    fn zero() -> FieldScalar {
        FieldScalar {
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

    fn from(n: &BigInt) -> FieldScalar {
        let n_mod = BigInt::modulus(n, &FE::q());
        let mut v = BigInt::to_vec(&n_mod);
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

        FieldScalar {
            purpose: "from_big_int",
            fe: SK::from_bytes(&bytes_array).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let mut bytes = SK::to_bytes(&self.fe);
        bytes.reverse();
        BigInt::from(&bytes[..])
    }

    fn q() -> BigInt {
        let q_u64: [u64; 4] = [
            0xffffffff00000001,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ];
        let to_bn = q_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    }

    fn add(&self, other: &SK) -> FieldScalar {
        let add_fe = FieldScalar {
            purpose: "other add",
            fe: *other,
        };
        let res = add_fe.fe.add(&self.fe);
        FieldScalar {
            purpose: "add",
            fe: res,
        }
    }

    fn mul(&self, other: &SK) -> FieldScalar {
        let mul_fe = FieldScalar {
            purpose: "other mul",
            fe: *other,
        };
        let res = mul_fe.fe.mul(&self.fe);
        FieldScalar {
            purpose: "mul",
            fe: res,
        }
    }

    fn sub(&self, other: &SK) -> FieldScalar {
        let other_neg = other.neg();
        let sub_fe = FieldScalar {
            purpose: "other sub",
            fe: other_neg,
        };
        self.add(&sub_fe.get_element())
    }

    fn invert(&self) -> FieldScalar {
        let inv_sc = self.fe.invert().unwrap();
        let inv_fe = FieldScalar {
            purpose: "inverse",
            fe: inv_sc,
        };
        inv_fe
    }
}

impl Debug for FieldScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose, self.fe,
        )
    }
}

impl PartialEq for FieldScalar {
    fn eq(&self, other: &FieldScalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Mul<FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn mul(self, other: FieldScalar) -> FieldScalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn mul(self, other: &'o FieldScalar) -> FieldScalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn add(self, other: FieldScalar) -> FieldScalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn add(self, other: &'o FieldScalar) -> FieldScalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for FieldScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for FieldScalar {
    fn deserialize<D>(deserializer: D) -> Result<FieldScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BLS12_381ScalarVisitor)
    }
}

struct BLS12_381ScalarVisitor;

impl<'de> Visitor<'de> for BLS12_381ScalarVisitor {
    type Value = FieldScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bls12_381")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<FieldScalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for GtPoint {
    fn eq(&self, other: &GtPoint) -> bool {
        self.get_element() == other.get_element()
    }
}

impl GtPoint {
    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    fn scalar_mul(&self, fe: &SK) -> GtPoint {
        let res = &self.ge * fe;
        let res_affine: Gt = res.into();
        GtPoint {
            purpose: "scalar_point_mul",
            ge: res_affine,
        }
    }

    fn add_point(&self, other: &PK) -> GtPoint {
        let ge_proj: Gt = self.ge.into();
        let res = other + &ge_proj;
        GtPoint {
            purpose: "combine",
            ge: res.into(),
        }
    }
    #[allow(dead_code)]
    fn sub_point(&self, other: &PK) -> GtPoint {
        let ge_proj: Gt = self.ge.into();
        let res = &ge_proj - other;

        GtPoint {
            purpose: "sub",
            ge: res.into(),
        }
    }
}

pub fn compute_pairing(g1: &G1, g2: &G2) -> GtPoint {
    GtPoint {
        purpose: "pairing",
        ge: pairing(&g1.get_element(), &g2.get_element()),
    }
}

impl Mul<FieldScalar> for GtPoint {
    type Output = GtPoint;
    fn mul(self, other: FieldScalar) -> GtPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for GtPoint {
    type Output = GtPoint;
    fn mul(self, other: &'o FieldScalar) -> GtPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for &'o GtPoint {
    type Output = GtPoint;
    fn mul(self, other: &'o FieldScalar) -> GtPoint {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<GtPoint> for GtPoint {
    type Output = GtPoint;
    fn add(self, other: GtPoint) -> GtPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o GtPoint> for GtPoint {
    type Output = GtPoint;
    fn add(self, other: &'o GtPoint) -> GtPoint {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o GtPoint> for &'o GtPoint {
    type Output = GtPoint;
    fn add(self, other: &'o GtPoint) -> GtPoint {
        self.add_point(&other.get_element())
    }
}

#[cfg(feature = "merkle")]
impl Hashable for GtPoint {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl<'de> Deserialize<'de> for GtPoint {
    fn deserialize<D>(deserializer: D) -> Result<GtPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["bytes_str"];
        deserializer.deserialize_struct("Bls12381GtPoint", FIELDS, Bls12381GtPointVisitor)
    }
}

struct Bls12381GtPointVisitor;

impl<'de> Visitor<'de> for Bls12381GtPointVisitor {
    type Value = GtPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Bls12381GtPointPoint")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;

    #[test]
    fn powers_of_g1_and_g2() {
        let a: G1 = ECPoint::generator();
        let b: G2 = ECPoint::generator();
        let scalar_factor: FE = ECScalar::new_random();
        let res_mul_a = a.scalar_mul(&scalar_factor.get_element());
        let res_mul_b = b.scalar_mul(&scalar_factor.get_element());
        let res_a_power = compute_pairing(&res_mul_a, &b);
        let res_b_power = compute_pairing(&a, &res_mul_b);
        assert_eq!(res_a_power, res_b_power);
    }

    #[test]
    fn powers_of_g1_and_gt_eq() {
        let a: G1 = ECPoint::generator();
        let b: G2 = ECPoint::generator();
        let scalar_factor: FE = ECScalar::new_random();
        let res_mul_a = a.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = compute_pairing(&res_mul_a, &b);
        let gt_direct_power = compute_pairing(&a, &b) * scalar_factor;
        assert_eq!(gt_direct_power, gt_from_a_power);
    }

    #[test]
    fn powers_of_g2_and_gt_eq() {
        let a: G1 = ECPoint::generator();
        let b: G2 = ECPoint::generator();
        let scalar_factor: FE = ECScalar::new_random();
        let res_mul_b = b.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = compute_pairing(&a, &res_mul_b);
        let gt_direct_power = compute_pairing(&a, &b) * scalar_factor;
        assert_eq!(gt_direct_power, gt_from_a_power);
    }
}
