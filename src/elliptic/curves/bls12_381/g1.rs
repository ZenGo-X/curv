/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

pub const SECRET_KEY_SIZE: usize = 32;
pub const COMPRESSED_SIZE: usize = 48;

use std::fmt;
use std::fmt::Debug;
use std::ops::{Add, Mul, Neg};
use std::str;

use ff_zeroize::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use pairing_plus::bls12_381::{Fr, G1Compressed, G1Uncompressed, G1};
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use pairing_plus::EncodedPoint;
use pairing_plus::{CurveAffine, CurveProjective, Engine};
use sha2::Sha256;

use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

pub type SK = <pairing_plus::bls12_381::Bls12 as ScalarEngine>::Fr;
pub type PK = <pairing_plus::bls12_381::Bls12 as Engine>::G1Affine;

use crate::arithmetic::traits::*;
use crate::BigInt;
use crate::ErrorKey::{self};

use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

use crate::elliptic::curves::traits::ECPoint;
use crate::elliptic::curves::traits::ECScalar;
#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
#[cfg(feature = "merkle")]
use merkle::Hashable;
use std::io::Cursor;

#[derive(Clone, Copy)]
pub struct FieldScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Copy)]
pub struct G1Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = G1Point;
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
            fe: SK::default(),
        }
    }

    fn get_element(&self) -> SK {
        self.fe.clone()
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

        // bytes_array.reverse();

        let mut repr = SK::default().into_repr();
        repr.read_be(Cursor::new(&bytes_array[..])).unwrap();
        FieldScalar {
            purpose: "from_big_int",
            fe: Fr::from_repr(repr).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let tmp = self.fe.into_repr();
        let scalar_u64 = tmp.as_ref().clone();

        let to_bn = scalar_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
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
        let mut add_fe = FieldScalar {
            purpose: "other add",
            fe: other.clone(),
        };
        add_fe.fe.add_assign(&self.fe);
        FieldScalar {
            purpose: "add",
            fe: add_fe.fe,
        }
    }

    fn mul(&self, other: &SK) -> FieldScalar {
        let mut mul_fe = FieldScalar {
            purpose: "other mul",
            fe: other.clone(),
        };
        mul_fe.fe.mul_assign(&self.fe);
        FieldScalar {
            purpose: "mul",
            fe: mul_fe.fe,
        }
    }

    fn sub(&self, other: &SK) -> FieldScalar {
        let mut other_neg = other.clone();
        other_neg.negate();
        let sub_fe = FieldScalar {
            purpose: "other sub",
            fe: other_neg,
        };
        self.add(&sub_fe.get_element())
    }

    fn invert(&self) -> FieldScalar {
        let sc = self.fe.clone();
        let inv_sc = sc.inverse().unwrap(); //TODO
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
        let v = BigInt::from_hex(s).map_err(E::custom)?;
        Ok(ECScalar::from(&v))
    }
}

impl Debug for G1Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.bytes_compressed_to_big_int().to_hex()
        )
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &G1Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for G1Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for G1Point {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = FieldScalar;

    fn base_point2() -> G1Point {
        const BASE_POINT2: [u8; 96] = [
            10, 18, 122, 36, 178, 251, 236, 31, 139, 88, 242, 163, 21, 198, 168, 208, 122, 195,
            135, 122, 7, 153, 197, 255, 160, 0, 89, 138, 39, 245, 105, 108, 99, 113, 78, 70, 130,
            172, 183, 57, 170, 180, 39, 32, 173, 29, 238, 62, 13, 166, 109, 90, 181, 17, 76, 247,
            26, 155, 130, 211, 18, 42, 235, 137, 225, 184, 210, 140, 54, 83, 233, 228, 226, 70,
            194, 50, 55, 116, 229, 2, 115, 227, 223, 31, 165, 39, 191, 209, 49, 127, 106, 196, 123,
            71, 70, 243,
        ];
        let mut point = G1Uncompressed::empty();
        point.as_mut().copy_from_slice(&BASE_POINT2);
        G1Point {
            purpose: "base_ge2",
            ge: point.into_affine().expect("invalid base_point"),
        }
    }

    fn generator() -> G1Point {
        G1Point {
            purpose: "base_fe",
            ge: PK::one(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    fn x_coor(&self) -> Option<BigInt> {
        let tmp = G1Uncompressed::from_affine(self.ge.clone());
        let bytes = tmp.as_ref();
        let x_coor = &bytes[0..COMPRESSED_SIZE];
        let bn = BigInt::from(x_coor);
        Some(bn)
    }

    fn y_coor(&self) -> Option<BigInt> {
        let tmp = G1Uncompressed::from_affine(self.ge.clone());
        let bytes = tmp.as_ref();
        let y_coor = &bytes[COMPRESSED_SIZE..COMPRESSED_SIZE * 2];
        let bn = BigInt::from(y_coor);
        Some(bn)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let tmp = G1Compressed::from_affine(self.ge.clone());
        let bytes = tmp.as_ref();
        let bn = BigInt::from(&bytes[..]);
        bn
    }

    fn from_bytes(bytes: &[u8]) -> Result<G1Point, ErrorKey> {
        let mut bytes_array_comp = [0u8; COMPRESSED_SIZE];
        match bytes.len() {
            0..=COMPRESSED_SIZE => {
                (&mut bytes_array_comp[COMPRESSED_SIZE - bytes.len()..]).copy_from_slice(bytes);
            }
            _ => {
                bytes_array_comp.copy_from_slice(&bytes[..COMPRESSED_SIZE]);
            }
        }

        let g1_comp = G1::deserialize(&mut bytes_array_comp[..].as_ref(), true).unwrap();
        let pk = G1Point {
            purpose: "from_bytes",
            ge: g1_comp.into_affine(), //TODO: handle error
        };
        return Ok(pk);
    }

    // in this case the opposite of from_bytes: takes compressed pk to COMPRESSED_SIZE bytes.
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut compressed_vec = vec![];
        PK::serialize(&self.ge, &mut compressed_vec, true)
            .expect("serializing into vec should always succeed");
        compressed_vec
    }

    fn scalar_mul(&self, fe: &SK) -> G1Point {
        let mut ge_proj: G1 = self.ge.into();
        ge_proj.mul_assign(fe.into_repr());
        G1Point {
            purpose: "scalar_point_mul",
            ge: ge_proj.into_affine(),
        }
    }

    fn add_point(&self, other: &PK) -> G1Point {
        let mut ge_proj: G1 = self.ge.into();
        ge_proj.add_assign_mixed(other);
        G1Point {
            purpose: "combine",
            ge: ge_proj.into_affine(),
        }
    }

    fn sub_point(&self, other: &PK) -> G1Point {
        let mut ge_proj: G1 = self.ge.into();
        ge_proj.sub_assign_mixed(other);
        G1Point {
            purpose: "sub",
            ge: ge_proj.into_affine(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> G1Point {
        // TODO
        unimplemented!();
    }
}

impl From<pairing_plus::bls12_381::G1Affine> for G1Point {
    fn from(point: PK) -> Self {
        G1Point {
            purpose: "from_point",
            ge: point,
        }
    }
}

impl Mul<FieldScalar> for G1Point {
    type Output = G1Point;
    fn mul(self, other: FieldScalar) -> G1Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for G1Point {
    type Output = G1Point;
    fn mul(self, other: &'o FieldScalar) -> G1Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for &'o G1Point {
    type Output = G1Point;
    fn mul(self, other: &'o FieldScalar) -> G1Point {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<G1Point> for G1Point {
    type Output = G1Point;
    fn add(self, other: G1Point) -> G1Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G1Point> for G1Point {
    type Output = G1Point;
    fn add(self, other: &'o G1Point) -> G1Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G1Point> for &'o G1Point {
    type Output = G1Point;
    fn add(self, other: &'o G1Point) -> G1Point {
        self.add_point(&other.get_element())
    }
}

impl Neg for G1Point {
    type Output = Self;
    fn neg(mut self) -> Self {
        self.ge.negate();
        self.purpose = "negated";
        self
    }
}

#[cfg(feature = "merkle")]
impl Hashable for G1Point {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Serialize for G1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from(&bytes[..]);
        let mut state = serializer.serialize_struct("Bls12381G1Point", 1)?;
        state.serialize_field("bytes_str", &bytes_as_bn.to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for G1Point {
    fn deserialize<D>(deserializer: D) -> Result<G1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["bytes_str"];
        deserializer.deserialize_struct("Bls12381G1Point", FIELDS, Bls12381G1PointVisitor)
    }
}

struct Bls12381G1PointVisitor;

impl<'de> Visitor<'de> for Bls12381G1PointVisitor {
    type Value = G1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Bls12381G1Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<G1Point, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let bytes_str = seq
            .next_element()?
            .ok_or_else(|| panic!("deserialization failed"))?;
        let bytes_bn = BigInt::from_hex(bytes_str).map_err(V::Error::custom)?;
        let bytes = BigInt::to_vec(&bytes_bn);
        Ok(G1Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<G1Point, E::Error> {
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
        let bytes = BigInt::to_vec(&bytes_bn);

        Ok(G1Point::from_bytes(&bytes[..]).expect("error deserializing point"))
    }
}

impl G1Point {
    /// Converts message to G1 point.
    ///
    /// Uses [expand_message_xmd][xmd] based on sha256.
    ///
    /// [xmd]: https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-10.html#name-expand_message_xmd-2
    pub fn hash_to_curve(message: &[u8]) -> Self {
        let cs = &[1u8];
        let point = <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, cs);
        G1Point {
            purpose: "hash_to_curve",
            ge: point.into_affine(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bincode;
    use serde_json;

    use pairing_plus::bls12_381::{G1Uncompressed, G1};
    use pairing_plus::hash_to_curve::HashToCurve;
    use pairing_plus::hash_to_field::ExpandMsgXmd;
    use pairing_plus::{CurveProjective, SubgroupCheck};
    use sha2::Sha256;

    use super::G1Point;
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::bls12_381::g1::{FE, GE};
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;

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
        let decoded: G1Point = bincode::deserialize(bin.as_slice()).unwrap();
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
            point_ab1.bytes_compressed_to_big_int().to_hex()
        );
        println!(
            "point ab2: {:?}",
            point_ab2.bytes_compressed_to_big_int().to_hex()
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
        println!("five_fe: {:?}", five_fe.clone());
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
        let a_inv_bn_1 = BigInt::mod_inv(&a_bn, &FE::q()).unwrap();
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
    fn base_point2_nothing_up_my_sleeve() {
        // Generate base_point2
        let cs = &[1u8];
        let msg = &[1u8];
        let point = <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, cs).into_affine();
        assert!(point.in_subgroup());

        // Print in uncompressed form
        use pairing_plus::EncodedPoint;
        let point_uncompressed = G1Uncompressed::from_affine(point);
        println!("Uncompressed base_point2: {:?}", point_uncompressed);

        // Check that ECPoint::base_point2() returns generated point
        let base_point2: GE = ECPoint::base_point2();
        assert_eq!(point, base_point2.ge);
    }
}
