// NIST P-256 elliptic curve utility functions.

use super::traits::{ECPoint, ECScalar};
use crate::arithmetic::traits::{Converter, Modulo};
use crate::BigInt;
use crate::ErrorKey;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use p256::ecdsa::VerifyKey;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand::{thread_rng, Rng};
use serde::de;
use serde::de::Visitor;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::ops::{Add, Mul, Sub};
use std::sync::atomic;
use std::{fmt, ptr};
use zeroize::Zeroize;

pub type SK = Scalar;
pub type PK = VerifyKey;

#[derive(Clone, Copy, Debug)]
pub struct Secp256r1Scalar {
    purpose: &'static str,
    fe: SK,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Secp256r1Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Secp256r1Point;
pub type FE = Secp256r1Scalar;

/* X coordinate of a point of unknown discrete logarithm.
Computed using a deterministic algorithm with the generator as input.
See test_base_point2 */
const BASE_POINT2_X: [u8; 32] = [
    0x70, 0xf7, 0x2b, 0xba, 0xc4, 0x0e, 0x8a, 0x59, 0x4c, 0x91, 0xa7, 0xba, 0xc3, 0x76, 0x59, 0x27,
    0x89, 0x10, 0x76, 0x4c, 0xd7, 0xc2, 0x0a, 0x7d, 0x65, 0xa5, 0x9a, 0x04, 0xb0, 0xac, 0x2a, 0xde,
];
const BASE_POINT2_Y: [u8; 32] = [
    0x30, 0xe2, 0xfe, 0xb3, 0x8d, 0x82, 0x4e, 0x0e, 0xa2, 0x95, 0x2f, 0x2a, 0x48, 0x5b, 0xbc, 0xdd,
    0x4c, 0x72, 0x8a, 0x74, 0xf4, 0xfa, 0xc7, 0xdc, 0x0d, 0xc9, 0x90, 0x8d, 0x9a, 0x8d, 0xc1, 0xa4,
];

impl Zeroize for Secp256r1Scalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, Secp256r1Scalar::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar for Secp256r1Scalar {
    type SecretKey = SK;

    fn new_random() -> Secp256r1Scalar {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        let gen_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&arr);
        Secp256r1Scalar {
            purpose: "random",
            fe: Scalar::from_bytes_reduced(&gen_arr),
        }
    }

    fn zero() -> Secp256r1Scalar {
        let zero_arr = [0u8; 32];
        let zero = unsafe { std::mem::transmute::<[u8; 32], Scalar>(zero_arr) };
        Secp256r1Scalar {
            purpose: "zero",
            fe: zero,
        }
    }

    fn get_element(&self) -> SK {
        self.fe.clone()
    }

    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Secp256r1Scalar {
        let curve_order = Secp256r1Scalar::q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0), &curve_order);
        let mut v = BigInt::to_vec(&n_reduced);
        const SECRET_KEY_SIZE: usize = 32;

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        let arr: GenericArray<u8, U32> = *GenericArray::from_slice(&v);

        Secp256r1Scalar {
            purpose: "from_big_int",
            fe: Scalar::from_bytes_reduced(&arr),
        }
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(self.fe.to_bytes().as_slice())
    }

    fn q() -> BigInt {
        const CURVE_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        BigInt::from(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &SK) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "add",
            fe: self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "mul",
            fe: self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "sub",
            fe: self.get_element() - other,
        }
    }

    fn invert(&self) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "invert",
            fe: self.fe.invert().unwrap(),
        }
    }
}

impl Mul<Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn mul(self, other: Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn mul(self, other: &'o Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn add(self, other: Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn add(self, other: &'o Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).add(&other.get_element())
    }
}

impl Sub<Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn sub(self, other: Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).sub(&other.get_element())
    }
}

impl<'o> Sub<&'o Secp256r1Scalar> for Secp256r1Scalar {
    type Output = Secp256r1Scalar;
    fn sub(self, other: &'o Secp256r1Scalar) -> Secp256r1Scalar {
        (&self).sub(&other.get_element())
    }
}

impl Serialize for Secp256r1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:0>64}", self.to_big_int().to_hex()))
    }
}

impl<'de> Deserialize<'de> for Secp256r1Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Secp256r1Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256r1ScalarVisitor)
    }
}

struct Secp256r1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256r1ScalarVisitor {
    type Value = Secp256r1Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256r1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Secp256r1Scalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for Secp256r1Scalar {
    fn eq(&self, other: &Secp256r1Scalar) -> bool {
        self.get_element().to_bytes() == other.get_element().to_bytes()
    }
}

impl Zeroize for Secp256r1Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for Secp256r1Point {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = Secp256r1Scalar;

    fn base_point2() -> Secp256r1Point {
        let mut v = vec![4 as u8];
        v.extend(BASE_POINT2_X.as_ref());
        v.extend(BASE_POINT2_Y.as_ref());
        Secp256r1Point::from_bytes(&v).unwrap()
    }

    fn generator() -> Secp256r1Point {
        Secp256r1Point {
            purpose: "base_fe",
            ge: VerifyKey::from_encoded_point(&AffinePoint::generator().to_encoded_point(true))
                .unwrap(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        BigInt::from(self.get_element().to_encoded_point(true).as_bytes())
    }

    fn x_coor(&self) -> Option<BigInt> {
        Some(BigInt::from(EncodedPoint::from(&self.ge).x().as_slice()))
    }

    fn y_coor(&self) -> Option<BigInt> {
        // need this back and forth conversion to get an uncompressed point
        let tmp = AffinePoint::from_encoded_point(&EncodedPoint::from(&self.ge)).unwrap();
        Some(BigInt::from(
            tmp.to_encoded_point(false).y().unwrap().as_slice(),
        ))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Secp256r1Point, ErrorKey> {
        let result = PK::new(&bytes);
        let test = result.map(|pk| Secp256r1Point {
            purpose: "random",
            ge: pk,
        });
        test.map_err(|_err| ErrorKey::InvalidPublicKey)
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        let tmp = AffinePoint::from_encoded_point(&EncodedPoint::from(&self.ge)).unwrap();
        tmp.to_encoded_point(false).as_ref().to_vec()
    }

    fn scalar_mul(&self, fe: &SK) -> Secp256r1Point {
        let point = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(&self.ge)).unwrap(),
        );
        let scalar = Scalar::from_bytes_reduced(&fe.to_bytes());
        Secp256r1Point {
            purpose: "mul",
            ge: VerifyKey::from_encoded_point(&(point * scalar).to_affine().to_encoded_point(true))
                .unwrap(),
        }
    }

    fn add_point(&self, other: &PK) -> Secp256r1Point {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(&self.ge)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(other)).unwrap(),
        );
        Secp256r1Point {
            purpose: "mul",
            ge: VerifyKey::from_encoded_point(
                &(point1 + point2).to_affine().to_encoded_point(true),
            )
            .unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Secp256r1Point {
        let point1 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(&self.ge)).unwrap(),
        );
        let point2 = ProjectivePoint::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from(other)).unwrap(),
        );
        Secp256r1Point {
            purpose: "sub",
            ge: VerifyKey::from_encoded_point(
                &(point1 - point2).to_affine().to_encoded_point(true),
            )
            .unwrap(),
        }
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Secp256r1Point {
        let mut vec_x = BigInt::to_vec(x);
        let mut vec_y = BigInt::to_vec(y);
        const COORDINATE_SIZE: usize = 32;
        assert!(vec_x.len() <= COORDINATE_SIZE, "x coordinate is too big.");
        assert!(vec_x.len() <= COORDINATE_SIZE, "y coordinate is too big.");
        if vec_x.len() < COORDINATE_SIZE {
            // pad
            let mut x_buffer = vec![0; COORDINATE_SIZE - vec_x.len()];
            x_buffer.extend_from_slice(&vec_x);
            vec_x = x_buffer
        }
        if vec_y.len() < COORDINATE_SIZE {
            // pad
            let mut y_buffer = vec![0; COORDINATE_SIZE - vec_y.len()];
            y_buffer.extend_from_slice(&vec_y);
            vec_y = y_buffer
        }

        let x_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&vec_x);
        let y_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&vec_y);
        Secp256r1Point {
            purpose: "base_fe",
            ge: VerifyKey::from_encoded_point(&EncodedPoint::from_affine_coordinates(
                &x_arr, &y_arr, false,
            ))
            .unwrap(),
        }
    }
}

impl Secp256r1Point {
    // derive point from BigInt
    fn from_bigint(i: &BigInt) -> Result<Secp256r1Point, ()> {
        let vec = BigInt::to_vec(i);
        let point = match Secp256r1Point::from_bytes(&vec) {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        Ok(point)
    }
}

impl Mul<Secp256r1Scalar> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn mul(self, other: Secp256r1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256r1Scalar> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn mul(self, other: &'o Secp256r1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256r1Scalar> for &'o Secp256r1Point {
    type Output = Secp256r1Point;
    fn mul(self, other: &'o Secp256r1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Secp256r1Point> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn add(self, other: Secp256r1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256r1Point> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn add(self, other: &'o Secp256r1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256r1Point> for &'o Secp256r1Point {
    type Output = Secp256r1Point;
    fn add(self, other: &'o Secp256r1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl Sub<Secp256r1Point> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn sub(self, other: Secp256r1Point) -> Self::Output {
        self.sub_point(&other.get_element())
    }
}

impl<'o> Sub<&'o Secp256r1Point> for Secp256r1Point {
    type Output = Secp256r1Point;
    fn sub(self, other: &'o Secp256r1Point) -> Self::Output {
        self.sub_point(&other.get_element())
    }
}

impl<'o> Sub<&'o Secp256r1Point> for &'o Secp256r1Point {
    type Output = Secp256r1Point;
    fn sub(self, other: &'o Secp256r1Point) -> Self::Output {
        self.sub_point(&other.get_element())
    }
}

impl Serialize for Secp256r1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!(
            "{:0>66}",
            self.bytes_compressed_to_big_int().to_hex()
        ))
    }
}

impl<'de> Deserialize<'de> for Secp256r1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256r1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256r1PointVisitor)
    }
}

struct Secp256r1PointVisitor;

impl<'de> Visitor<'de> for Secp256r1PointVisitor {
    type Value = Secp256r1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256r1Point")
    }

    fn visit_str<E>(self, s: &str) -> Result<Secp256r1Point, E>
    where
        E: de::Error,
    {
        match Secp256r1Point::from_bigint(&BigInt::from_hex(s)) {
            Ok(v) => Ok(v),
            Err(_) => Err(E::custom(format!(
                "Error deriving Secp256r1Point from string: {}",
                s
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BigInt, ErrorKey};
    use super::{Secp256r1Point, Secp256r1Scalar};
    use crate::arithmetic::traits::{Converter, Modulo, Samplable};
    use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use crate::cryptographic_primitives::hashing::traits::Hash;
    use crate::elliptic::curves::traits::{ECPoint, ECScalar};

    fn random_point() -> Secp256r1Point {
        let random_scalar: Secp256r1Scalar = Secp256r1Scalar::new_random();
        let base_point = Secp256r1Point::generator();
        let pk = base_point.scalar_mul(&random_scalar.get_element());
        Secp256r1Point {
            purpose: "random_point",
            ge: pk.get_element(),
        }
    }

    #[test]
    fn serialize_sk() {
        let scalar: Secp256r1Scalar = ECScalar::from(&BigInt::from(123456));
        let s = serde_json::to_string(&scalar).expect("Failed in serialization");
        assert_eq!(
            s,
            "\"000000000000000000000000000000000000000000000000000000000001e240\""
        );
    }

    #[test]
    fn serialize_rand_pk_verify_pad() {
        let vx = BigInt::from_hex(
            &"9e6b4c9775d5af0aff94a55035a2b039f7cfc19b9e67004f190ddfaada82b405".to_string(),
        );

        let vy = BigInt::from_hex(
            &"d3fa4d180ea04d8da373bb61782bc6b509f7b6e374d6a47b253e4853ad1cd5fc".to_string(),
        );
        Secp256r1Point::from_coor(&vx, &vy); // x and y of size 32

        let x = BigInt::from_hex(
            &"2d054d254d1d112b1e7a134780ae7975a2a57b35089b2afa45dc42ed9afe1b".to_string(),
        );

        let y = BigInt::from_hex(
            &"16f436c897a9733a4d83eed96147b273348c98fb680d7361d915ec6b5ce761ca".to_string(),
        );
        Secp256r1Point::from_coor(&x, &y); // x and y not of size 32 each

        let r = random_point();
        let r_expected = Secp256r1Point::from_coor(&r.x_coor().unwrap(), &r.y_coor().unwrap());
        assert_eq!(r.x_coor().unwrap(), r_expected.x_coor().unwrap());
        assert_eq!(r.y_coor().unwrap(), r_expected.y_coor().unwrap());
    }

    #[test]
    fn deserialize_sk() {
        let s = "\"1e240\"";
        let dummy: Secp256r1Scalar = serde_json::from_str(s).expect("Failed in serialization");

        let sk: Secp256r1Scalar = ECScalar::from(&BigInt::from(123456));

        assert_eq!(dummy.to_big_int(), sk.to_big_int());
    }

    #[test]
    fn serialize_pk() {
        let pk = Secp256r1Point::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let expected = pk.bytes_compressed_to_big_int().to_hex();
        assert_eq!(
            s,
            serde_json::to_string(&("0".to_string() + &expected)).unwrap()
        );
        let des_pk: Secp256r1Point = serde_json::from_str(&s).expect("Failed in serialization");
        assert_eq!(des_pk.ge, pk.ge);
    }

    #[test]
    fn bincode_pk() {
        let pk = Secp256r1Point::generator();
        let bin = bincode::serialize(&pk).unwrap();
        let decoded: Secp256r1Point = bincode::deserialize(bin.as_slice()).unwrap();
        assert_eq!(decoded.get_element(), pk.get_element());
    }

    #[test]
    fn test_serdes_pk() {
        let pk = Secp256r1Point::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: Secp256r1Point = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk.get_element(), pk.get_element());

        let pk = Secp256r1Point::base_point2();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: Secp256r1Point = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk.get_element(), pk.get_element());
    }

    #[test]
    #[should_panic]
    fn test_serdes_bad_pk() {
        let pk = Secp256r1Point::generator();
        let mut s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        s = s.replace("2770", "2780");
        let des_pk: Secp256r1Point = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

    #[test]
    fn test_from_bytes() {
        let vec = BigInt::to_vec(&BigInt::from(1337));
        let result = Secp256r1Point::from_bytes(&vec);
        assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey)
    }

    #[test]
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256r1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_from_bytes_4() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256r1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_from_bytes_5() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
            6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
            5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3,
            4, 5, 6,
        ];
        let result = Secp256r1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_add_sub() {
        let q = Secp256r1Scalar::q();
        let start: Secp256r1Scalar = ECScalar::new_random();
        let b: Secp256r1Scalar = ECScalar::new_random();
        let tmp = BigInt::mod_add(&start.to_big_int(), &b.to_big_int(), &q);
        let end = BigInt::mod_sub(&tmp, &b.to_big_int(), &q);
        assert_eq!(start.to_big_int(), end);
    }

    #[test]
    fn test_minus_point() {
        let a: Secp256r1Scalar = ECScalar::new_random();
        let b: Secp256r1Scalar = ECScalar::new_random();
        let b_bn = b.to_big_int();
        let q = Secp256r1Scalar::q();
        let minus_b = BigInt::mod_sub(&q, &b_bn, &q);
        let a_minus_b = BigInt::mod_add(&a.to_big_int(), &minus_b, &q);
        let a_minus_b_fe: Secp256r1Scalar = ECScalar::from(&a_minus_b);
        let base: Secp256r1Point = ECPoint::generator();
        let point_ab1 = base.clone() * a_minus_b_fe;
        let point_a = base.clone() * a;
        let point_b = base.clone() * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1.get_element(), point_ab2.get_element());
    }

    #[test]
    fn test_simple_inversion2() {
        let a: Secp256r1Scalar = ECScalar::from(&BigInt::from(2));
        let a_inv = a.invert();
        let a_inv_int = a_inv.to_big_int();
        assert_eq!(
            a_inv_int,
            BigInt::from_hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"),
        );
    }

    #[test]
    fn test_simple_inversion3() {
        let a: Secp256r1Scalar = ECScalar::from(&BigInt::from(1234567890));
        let a_inv = a.invert().to_big_int();
        assert_eq!(
            a_inv,
            BigInt::from_hex("93a24a3b7e3b3a49a5acf862e8360bdd456e4c095dec9b97772bb758f725715a"),
        );
    }

    #[test]
    fn test_invert() {
        let a_bn = BigInt::sample(256);
        let a: Secp256r1Scalar = ECScalar::from(&a_bn);
        let a_inv = a.invert();
        let a_inv_bn_1 = BigInt::mod_inv(&a_bn, &Secp256r1Scalar::q());
        let a_inv_bn_2 = a_inv.to_big_int();
        assert_eq!(a_inv_bn_1, a_inv_bn_2);
    }

    #[test]
    fn test_scalar_mul_scalar() {
        let a: Secp256r1Scalar = ECScalar::new_random();
        let b: Secp256r1Scalar = ECScalar::new_random();
        let c1 = a.mul(&b.get_element());
        let c2 = a * b;
        assert_eq!(c1.get_element().to_bytes(), c2.get_element().to_bytes());
    }

    #[test]
    fn test_scalar_mul1() {
        let base_point = Secp256r1Point::generator();
        let int: Secp256r1Scalar = ECScalar::from(&BigInt::from(1));
        let test = base_point * int;
        assert_eq!(
            test.x_coor().unwrap().to_hex(),
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296".to_lowercase()
        );
        assert_eq!(
            test.y_coor().unwrap().to_hex(),
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5".to_lowercase()
        );
    }

    #[test]
    fn test_scalar_mul2() {
        let base_point = Secp256r1Point::generator();
        let int: Secp256r1Scalar = ECScalar::from(&BigInt::from(2));
        let test = base_point * int;
        assert_eq!(
            test.x_coor().unwrap().to_hex(),
            "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978".to_lowercase()
        );
        assert_eq!(
            format!("{:0>64}", test.y_coor().unwrap().to_hex()),
            "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1".to_lowercase()
        );
    }

    #[test]
    fn test_scalar_mul3() {
        let base_point = Secp256r1Point::generator();
        let int: Secp256r1Scalar = ECScalar::from(&BigInt::from_hex(
            "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
        ));
        let test = base_point * int;
        assert_eq!(
            test.x_coor().unwrap().to_hex(),
            "4F6DD42033C0666A04DFC107F4CB4D5D22E33AE178006803D967CB25D95B7DB4".to_lowercase()
        );
        assert_eq!(
            format!("{:0>64}", test.y_coor().unwrap().to_hex()),
            "085DB1B0952D8E081A3E13398A89911A038AAB054AE3E26718A5E582ED9FDD38".to_lowercase()
        );
    }

    #[test]
    fn test_pk_to_key_slice() {
        for _ in 1..200 {
            let r = Secp256r1Scalar::new_random();
            let rg = Secp256r1Point::generator() * &r;
            let key_slice = rg.pk_to_key_slice();
            assert!(key_slice.len() == 65);
            assert!(key_slice[0].clone() == 4);
            let rg_prime: Secp256r1Point = ECPoint::from_bytes(&key_slice).unwrap();
            assert_eq!(rg_prime.get_element(), rg.get_element());
        }
    }

    #[test]
    fn test_base_point2() {
        /* Show that base_point2() is returning a point of unknown discrete logarithm.
        It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
        as the initial input, until receiving a valid Secp256r1 point. */

        let base_point2 = Secp256r1Point::base_point2();

        let g = Secp256r1Point::generator();
        let mut hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        hash = HSha256::create_hash(&[&hash]);

        assert_eq!(hash, base_point2.x_coor().unwrap(),);

        // check that base_point2 is indeed on the curve (from_coor() will fail otherwise)
        assert_eq!(
            Secp256r1Point::from_coor(
                &base_point2.x_coor().unwrap(),
                &base_point2.y_coor().unwrap()
            )
            .get_element(),
            base_point2.get_element()
        );
    }

    #[test]
    fn scalar_bigint_conversion1() {
        let int = BigInt::sample(256);
        let scalar: Secp256r1Scalar = ECScalar::from(&int);
        assert_eq!(scalar.to_big_int(), int);
    }

    #[test]
    fn point_bigint_conversion1() {
        let g = Secp256r1Point::generator();
        let h = g.bytes_compressed_to_big_int();
        let i = Secp256r1Point::from_bigint(&h).unwrap();
        assert_eq!(i.get_element(), g.get_element());
    }

    #[test]
    fn point_bigint_conversion2() {
        let g = Secp256r1Point::generator();
        let r: Secp256r1Scalar = ECScalar::from(&BigInt::sample(256));
        let point = g * r;
        let point_int = point.bytes_compressed_to_big_int();
        let point_test = Secp256r1Point::from_bigint(&point_int).unwrap();
        assert_eq!(point.get_element(), point_test.get_element());
    }

    #[test]
    fn scalar_bigint_conversion2() {
        let i = Secp256r1Scalar::new_random();
        let int = i.to_big_int();
        let j: Secp256r1Scalar = ECScalar::from(&int);
        assert_eq!(i.to_big_int(), j.to_big_int());
    }

    #[test]
    fn pk_to_hex() {
        let secret =
            BigInt::from_hex("79196b247effbe3192763a5c37b18f5d89e7d0a8c83d246917add0a842d5af8b");
        let sk: Secp256r1Scalar = ECScalar::from(&secret);
        let g = Secp256r1Point::generator();
        let h = g * sk;
        assert_eq!(
            format!("{:0>66}", h.bytes_compressed_to_big_int().to_str_radix(16)),
            "025c31225f77535b1ceb7f603ef73627bf096a1efb65c1fdf0f7c1c9d64cf167ca"
        );
    }

    #[test]
    fn scalar_from_bigint() {
        let r = Secp256r1Scalar::new_random();
        let int = r.to_big_int();
        let s: Secp256r1Scalar = ECScalar::from(&int);
        assert_eq!(r.to_big_int(), s.to_big_int());
    }

    #[test]
    fn add_sub_point() {
        let g = Secp256r1Point::generator();
        let i: Secp256r1Scalar = ECScalar::from(&BigInt::from(3));
        assert_eq!(
            (g.clone() + g.clone() + g.clone()).get_element(),
            (g.clone() * i).get_element()
        );
        assert_eq!(
            (g.clone() + g.clone()).get_element(),
            (g.clone() + g.clone() - g.clone() + g.clone()).get_element()
        );
    }

    #[test]
    fn add_scalar() {
        let i: Secp256r1Scalar = ECScalar::from(&BigInt::from(1));
        let j: Secp256r1Scalar = ECScalar::from(&BigInt::from(2));
        assert_eq!((i.clone() + i.clone()).to_big_int(), j.to_big_int());
        assert_eq!(
            (i.clone() + i.clone() + i.clone() + i.clone()).to_big_int(),
            (j.clone() + j.clone()).to_big_int()
        );
    }

    #[test]
    fn sub_scalar() {
        let i: Secp256r1Scalar = ECScalar::from(&BigInt::from(1));
        assert_eq!(
            (i.clone() + i.clone() - i.clone()).to_big_int(),
            i.to_big_int()
        );
        let j: Secp256r1Scalar = ECScalar::from(&BigInt::from(2));
        assert_eq!(
            (j.clone() + j.clone() - j.clone()).to_big_int(),
            j.to_big_int()
        );
        let k = Secp256r1Scalar::new_random();
        assert_eq!(
            (k.clone() + k.clone() - k.clone()).to_big_int(),
            k.to_big_int()
        );
    }

    #[test]
    fn mul_scalar() {
        let i: Secp256r1Scalar = ECScalar::from(&BigInt::from(1));
        let j: Secp256r1Scalar = ECScalar::from(&BigInt::from(2));
        assert_eq!((j.clone() * i.clone()).to_big_int(), j.to_big_int());
    }
}
