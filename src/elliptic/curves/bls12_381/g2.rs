/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// jubjub : https://z.cash/technology/jubjub/
use std::fmt::Debug;
use std::str;
pub const SECRET_KEY_SIZE: usize = 32;
use crate::arithmetic::traits::Converter;
use crate::cryptographic_primitives::hashing::hash_sha512::HSha512;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::traits::{ECPoint, ECScalar};

use bls12_381::G2Affine;
use bls12_381::G2Projective;
use bls12_381::Scalar;

use serde::de;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

use std::fmt;
use std::ops::{Add, Mul};
pub type SK = Scalar;
// We use G2 only
pub type PK = G2Affine;

use crate::arithmetic::traits::Samplable;
use crate::BigInt;
use crate::ErrorKey::{self};

use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

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
#[derive(Clone, Copy)]
pub struct G2Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = G2Point;
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
        formatter.write_str("g2")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<FieldScalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl Debug for G2Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.bytes_compressed_to_big_int().to_str_radix(16)
        )
    }
}

impl PartialEq for G2Point {
    fn eq(&self, other: &G2Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for G2Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for G2Point {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = FieldScalar;

    fn base_point2() -> G2Point {
        // 48 bytes
        let g: GE = ECPoint::generator();
        let mut hash = HSha512::create_hash(&[&g.bytes_compressed_to_big_int()]);
        hash = HSha512::create_hash(&[&hash]);
        hash = HSha512::create_hash(&[&hash]);
        let mut bytes = BigInt::to_vec(&hash);
        let end_vector_hash = HSha512::create_hash(&[&hash]);
        let bytes_end = BigInt::to_vec(&end_vector_hash);
        bytes[47] = 184; //Fq must be canoncial + specific flags. This byte is the same as the one from the generator.
        bytes[0] = 184;
        bytes.extend_from_slice(&bytes_end[0..32]);
        let h: GE = ECPoint::from_bytes(&bytes[..]).unwrap();
        let bp2_proj: G2Projective = h.ge.into();
        let bp2_proj_in_g1 = bp2_proj.clear_cofactor();
        G2Point {
            purpose: "base point 2",
            ge: bp2_proj_in_g1.into(),
        }
    }

    fn generator() -> G2Point {
        G2Point {
            purpose: "base_fe",
            ge: G2Affine::generator(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    fn x_coor(&self) -> Option<BigInt> {
        let bytes = G2Affine::to_uncompressed(&self.ge);
        let x_coor = &bytes[0..96];
        let bn = BigInt::from(x_coor);
        Some(bn)
    }

    fn y_coor(&self) -> Option<BigInt> {
        let bytes = G2Affine::to_uncompressed(&self.ge);
        let y_coor = &bytes[96..192];
        let bn = BigInt::from(y_coor);
        Some(bn)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let bytes = self.ge.to_compressed();
        let bn = BigInt::from(&bytes[..]);
        bn
    }

    fn from_bytes(bytes: &[u8]) -> Result<G2Point, ErrorKey> {
        let mut bytes_array = [0u8; 96];
        bytes_array[96 - bytes.len()..].copy_from_slice(bytes);
        let pk = G2Point {
            purpose: "random",
            ge: G2Affine::from_compressed_unchecked(&bytes_array).unwrap(),
        };
        return Ok(pk);
    }

    // in this case the opposite of from_bytes: takes compressed pk to 96 bytes.
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let bytes = G2Affine::to_compressed(&self.ge);
        let mut compressed_vec = Vec::new();
        compressed_vec.extend_from_slice(&bytes[..]);
        compressed_vec
    }

    fn scalar_mul(&self, fe: &SK) -> G2Point {
        let res = &self.ge * fe;
        let res_affine: G2Affine = res.into();
        G2Point {
            purpose: "scalar_point_mul",
            ge: res_affine,
        }
    }

    fn add_point(&self, other: &PK) -> G2Point {
        let ge_proj: G2Projective = self.ge.into();
        let res = other + &ge_proj;
        G2Point {
            purpose: "combine",
            ge: res.into(),
        }
    }

    fn sub_point(&self, other: &PK) -> G2Point {
        let ge_proj: G2Projective = self.ge.into();
        let res = &ge_proj - other;

        G2Point {
            purpose: "sub",
            ge: res.into(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> G2Point {
        // TODO
        unimplemented!();
    }
}

impl Mul<FieldScalar> for G2Point {
    type Output = G2Point;
    fn mul(self, other: FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for G2Point {
    type Output = G2Point;
    fn mul(self, other: &'o FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for &'o G2Point {
    type Output = G2Point;
    fn mul(self, other: &'o FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<G2Point> for G2Point {
    type Output = G2Point;
    fn add(self, other: G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G2Point> for G2Point {
    type Output = G2Point;
    fn add(self, other: &'o G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G2Point> for &'o G2Point {
    type Output = G2Point;
    fn add(self, other: &'o G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

#[cfg(feature = "merkle")]
impl Hashable for G2Point {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Serialize for G2Point {
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

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> Result<G2Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["bytes_str"];
        deserializer.deserialize_struct("JujubPoint", FIELDS, JubjubPointVisitor)
    }
}

struct JubjubPointVisitor;

impl<'de> Visitor<'de> for JubjubPointVisitor {
    type Value = G2Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("JubjubCurvePoint")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<G2Point, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes_str = seq
            .next_element()?
            .ok_or_else(|| panic!("deserialization failed"))?;
        let bytes_bn = BigInt::from_hex(bytes_str);
        let bytes = BigInt::to_vec(&bytes_bn);
        Ok(G2Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<G2Point, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => panic!("deserialization failed!"),
            }
        }
        let bytes_bn = BigInt::from_hex(&bytes_str);
        let bytes = BigInt::to_vec(&bytes_bn);

        Ok(G2Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldScalar, G2Point};
    use crate::arithmetic::traits::Modulo;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;
    use bincode;
    use serde_json;

    type GE = G2Point;
    type FE = FieldScalar;

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
        let bin = bincode::serialize(&pk).unwrap();
        let decoded: G2Point = bincode::deserialize(bin.as_slice()).unwrap();
        assert_eq!(decoded, pk);
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
        println!(
            "point ab1: {:?}",
            point_ab1.bytes_compressed_to_big_int().to_str_radix(16)
        );
        println!(
            "point ab2: {:?}",
            point_ab2.bytes_compressed_to_big_int().to_str_radix(16)
        );

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
