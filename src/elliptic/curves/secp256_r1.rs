use crate::arithmetic::traits::{Converter, Modulo};
use crate::{BigInt, ErrorKey};
use crate::elliptic::curves::traits::{ECScalar, ECPoint};

use serde::de;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use std::ptr;
use std::sync::atomic;
use rand::{thread_rng, Rng};
use ring::signature::{
    cpu,
    untrusted,
    ec::{
        suite_b::{ops::*, curve::P256}, Seed, PublicKey
    }
};
use zeroize::Zeroize;
use std::ptr::null;

/// The size (in bytes) of a message
pub const MESSAGE_SIZE: usize = 32;

/// The size (in bytes) of a P-256 signature
pub const SIGNATURE_SIZE: usize = 64;

/// The size (in bytes) of a P-256 secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized P-256 public key
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The size (in bytes) of a serialized P-256 uncompressed public key
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

pub const FIELD_MODULO: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

pub const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

pub const SEED: [u8; 20] = [
    0xC4, 0x9D, 0x36, 0x08, 0x86, 0xE7, 0x04, 0x93,
    0x6A, 0x66, 0x78, 0xE1, 0x13, 0x9D, 0x26, 0xB7,
    0x81, 0x9F, 0x7E, 0x90,
];

pub const CURVE_A: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];

pub const CURVE_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];

pub const GENERATOR_X: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
];

pub const GENERATOR_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/* X coordinate of a base point of unknown discrete logarithm.
   Computed using a deterministic algorithm with a (supposedly) random input seed.
   See test_ec_point_base_point2 */
pub const BASE_POINT2_X: [u8; 32] = [
    0x70, 0xf7, 0x2b, 0xba, 0xc4, 0x0e, 0x8a, 0x59,
    0x4c, 0x91, 0xa7, 0xba, 0xc3, 0x76, 0x59, 0x27,
    0x89, 0x10, 0x76, 0x4c, 0xd7, 0xc2, 0x0a, 0x7d,
    0x65, 0xa5, 0x9a, 0x04, 0xb0, 0xac, 0x2a, 0xde,
];

pub const BASE_POINT2_Y: [u8; 32] = [
    0xcf, 0x1d, 0x01, 0x4b, 0x72, 0x7d, 0xb1, 0xf2,
    0x5d, 0x6a, 0xd0, 0xd5, 0xb7, 0xa4, 0x43, 0x22,
    0xb3, 0x8d, 0x75, 0x8c, 0x0b, 0x05, 0x38, 0x23,
    0xf2, 0x36, 0x6f, 0x72, 0x65, 0x72, 0x3e, 0x5b,
];

#[derive(Clone, Debug, Copy)]
pub struct Secp256r1Scalar {
    purpose: &'static str,
    fe: Seed,
}

#[derive(Clone, Debug, Copy)]
pub struct Secp256r1Point {
    purpose: &'static str,
    ge: PublicKey,
}

pub type GE = Secp256r1Point;
pub type FE = Secp256r1Scalar;

impl Secp256r1Point {
    pub fn random_point() -> Secp256r1Point {
        let random_scalar: Secp256r1Scalar = Secp256r1Scalar::new_random();
        let base_point = Secp256r1Point::generator();
        let pk = base_point.scalar_mul(&random_scalar.get_element());
        Secp256r1Point {
            purpose: "random_point",
            ge: pk.get_element(),
        }
    }

    pub fn base_point2() -> Secp256r1Point {
        Secp256r1Point::from_coor(
            &BigInt::from(BASE_POINT2_X.as_ref()),
            &BigInt::from(BASE_POINT2_Y.as_ref()),
        )
    }

    fn to_negative(&self) -> Result<Self, ErrorKey>  {
        let order = BigInt::from(&FIELD_MODULO[..]);
        let x = self.x_coor().unwrap();
        let y = self.y_coor().unwrap();
        let minus_y = BigInt::mod_sub(&order, &y, &order);

        let x_vec = BigInt::to_vec(&x);
        let y_vec = BigInt::to_vec(&minus_y);

        let mut template_x = vec![0; 32 - x_vec.len()];
        template_x.extend_from_slice(&x_vec);
        let mut x_vec = template_x;

        let mut template_y = vec![0; 32 - y_vec.len()];
        template_y.extend_from_slice(&y_vec);
        let y_vec = template_y;

        x_vec.extend_from_slice(&y_vec);

        Self::from_bytes(&x_vec)
    }
}

impl Zeroize for Secp256r1Scalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar<Seed> for Secp256r1Scalar {
    fn new_random() -> Secp256r1Scalar {
        let mut arr = [0u8; SECRET_KEY_SIZE];
        thread_rng().fill(&mut arr[..]);
        Secp256r1Scalar {
            purpose: "random",
            fe: Seed::from_bytes(
                &P256,
                untrusted::Input::from(&arr.to_vec()),
                cpu::features()  // TODO: remove cpu to be encapsulated on the seed
            ).unwrap()  // TODO: handle unwrap
        }
    }

    fn zero() -> Self {
        Secp256r1Scalar {
            purpose: "zero",
            fe: Seed::zero(&P256, cpu::features()),
        }
    }

    fn get_element(&self) -> Seed {
        self.fe
    }

    fn set_element(&mut self, element: Seed) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Secp256r1Scalar {
        let curve_order = Self::q();
        let n_reduced = n.mod_floor(&curve_order);
        let mut v = BigInt::to_vec(&n_reduced);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }

        Secp256r1Scalar {
            purpose: "from_big_int",
            fe: Seed::from_bytes(
                &P256,
                untrusted::Input::from(&v),
                cpu::features()
            ).unwrap()
        }
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(self.fe.bytes_less_safe())
    }

    fn q() -> BigInt {
        BigInt::from(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &Seed) -> Secp256r1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_add(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256r1Scalar {
            purpose: "add",
            fe: res.get_element(),
        }
    }

    fn mul(&self, other: &Seed) -> Secp256r1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_mul(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256r1Scalar {
            purpose: "mul",
            fe: res.get_element(),
        }
    }

    fn sub(&self, other: &Seed) -> Secp256r1Scalar {
        let other_scalar = Secp256r1Scalar {
            purpose: "sub",
            fe: other.clone(),
        };
        let res: FE = ECScalar::from(&BigInt::mod_sub(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256r1Scalar {
            purpose: "sub",
            fe: res.get_element(),
        }
    }

    fn invert(&self) -> Secp256r1Scalar {
        let bignum = self.to_big_int();
        let bn_inv = bignum.invert(&FE::q()).unwrap();
        ECScalar::from(&bn_inv)
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

impl Serialize for Secp256r1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
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

impl Serialize for Secp256r1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("Secp256r1Point", 2)?;
        state.serialize_field("x", &self.x_coor().unwrap().to_hex())?;
        state.serialize_field("y", &self.y_coor().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Secp256r1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256r1Point, D::Error>
        where
            D: Deserializer<'de>,
    {
        let fields = &["x", "y"];
        deserializer.deserialize_struct("Secp256r1Point", fields, Secp256r1PointVisitor)
    }
}

struct Secp256r1PointVisitor;

impl<'de> Visitor<'de> for Secp256r1PointVisitor {
    type Value = Secp256r1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256r1Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Secp256r1Point, V::Error>
        where
            V: SeqAccess<'de>,
    {
        let x = seq
            .next_element()?
            .ok_or_else(|| panic!("deserialization failed"))?;
        let y = seq
            .next_element()?
            .ok_or_else(|| panic!("deserialization failed"))?;

        let bx = BigInt::from_hex(x);
        let by = BigInt::from_hex(y);

        Ok(Secp256r1Point::from_coor(&bx, &by))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Secp256r1Point, E::Error> {
        let mut x = String::new();
        let mut y = String::new();

        while let Some(ref key) = map.next_key::<String>()? {
            let v = map.next_value::<String>()?;
            if key == "x" {
                x = v
            } else if key == "y" {
                y = v
            } else {
                panic!("Serialization failed!")
            }
        }

        let bx = BigInt::from_hex(&x);
        let by = BigInt::from_hex(&y);

        Ok(Secp256r1Point::from_coor(&bx, &by))
    }
}

impl PartialEq for Secp256r1Scalar {
    fn eq(&self, other: &Secp256r1Scalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl PartialEq for Secp256r1Point {
    fn eq(&self, other: &Secp256r1Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for Secp256r1Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint<PublicKey, Seed> for Secp256r1Point {
    fn generator() -> Secp256r1Point {
        Secp256r1Point::from_coor(
            &BigInt::from(GENERATOR_X.as_ref()),
            &BigInt::from(GENERATOR_Y.as_ref()),
        )
    }

    fn get_element(&self) -> PublicKey {
        self.ge
    }

    fn x_coor(&self) -> Option<BigInt> {
        let bytes_uncompressed = self.ge.serialize_uncompressed();
        let x = &bytes_uncompressed[1..PUBLIC_KEY_SIZE];
        Some(BigInt::from(x))
    }

    fn y_coor(&self) -> Option<BigInt> {
        let bytes_uncompressed = self.ge.serialize_uncompressed();
        let y = &bytes_uncompressed[PUBLIC_KEY_SIZE..UNCOMPRESSED_PUBLIC_KEY_SIZE];
        Some(BigInt::from(y))
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let bytes_uncompressed = self.ge.serialize_uncompressed();
        let mut bytes_compressed: [u8; PUBLIC_KEY_SIZE] = [0u8; PUBLIC_KEY_SIZE];
        bytes_compressed.copy_from_slice(&bytes_uncompressed[..PUBLIC_KEY_SIZE]);
        let is_y_even = bytes_uncompressed[UNCOMPRESSED_PUBLIC_KEY_SIZE - 1] & 1 == 0;
        if is_y_even {
            bytes_compressed[0] = 2;
        } else {
            bytes_compressed[0] = 3;
        }
        BigInt::from(bytes_compressed.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorKey> {
        // TODO: support other lengths
        match bytes.len() {
            33..=64 => {
                // pad with 04 and then 00 bytes
                let mut bytes_uncompressed_vec = vec![0; UNCOMPRESSED_PUBLIC_KEY_SIZE - bytes.len()];
                bytes_uncompressed_vec[0] = 04;
                bytes_uncompressed_vec.extend_from_slice(bytes);

                match PublicKey::new(
                    bytes_uncompressed_vec.as_slice(),
                    &p256::PUBLIC_KEY_OPS,
                ) {
                    Err(_) => Err(ErrorKey::InvalidPublicKey),
                    Ok(public_key) => Ok(Secp256r1Point {
                        purpose: "random",
                        ge: public_key,
                    })
                }
            },
            _ => {
                Err(ErrorKey::InvalidPublicKey)
            }
        }
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        self.get_element()
            .serialize_uncompressed()[..UNCOMPRESSED_PUBLIC_KEY_SIZE]
            .to_vec()
    }

    fn scalar_mul(&self, fe: &Seed) -> Self {
        let public_key = self.ge
            .scalar_mul(fe, &p256::PRIVATE_KEY_OPS, &p256::PUBLIC_KEY_OPS)
            .unwrap();

        Secp256r1Point {
            purpose: "scalar_mul",
            ge: public_key,
        }
    }

    fn add_point(&self, other: &PublicKey) -> Self {
        let sum_public_key = self
            .get_element()
            .add_point(&P256, &other, &p256::PRIVATE_KEY_OPS, &p256::PUBLIC_KEY_OPS)
            .unwrap();

        Secp256r1Point {
            purpose: "add_point",
            ge: sum_public_key,
        }
    }

    fn sub_point(&self, other: &PublicKey) -> Self {
        let other_point = Secp256r1Point {
            purpose: "sub",
            ge: *other,
        };

        let minus_other = other_point.to_negative().unwrap();
        self.add_point(&minus_other.get_element())
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Self {
        // TODO: use common buffer utils for padding
        let x_bytes_vec = BigInt::to_vec(x);
        let mut x_bytes_padded = vec![0; PUBLIC_KEY_SIZE - 1 - x_bytes_vec.len()];
        x_bytes_padded.extend_from_slice(x_bytes_vec.as_slice());

        let y_bytes_vec = BigInt::to_vec(y);
        let mut y_bytes_padded = vec![0; PUBLIC_KEY_SIZE - 1 - y_bytes_vec.len()];
        y_bytes_padded.extend_from_slice(y_bytes_vec.as_slice());

        let mut bytes = vec![];
        bytes.extend_from_slice(x_bytes_padded.as_ref());
        bytes.extend_from_slice(y_bytes_padded.as_ref());
        Self::from_bytes(bytes.as_ref()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BigInt,
        ECScalar,
        ECPoint,
        Secp256r1Scalar,
        Secp256r1Point,
        Converter,
        UNCOMPRESSED_PUBLIC_KEY_SIZE,
    };
    use serde_json;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use hex;
    use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use crate::cryptographic_primitives::hashing::traits::Hash;

    #[test]
    fn test_ec_scalar_from_bigint() {
        let scalar: Secp256r1Scalar = ECScalar::from(&BigInt::from(123456));
        let s = serde_json::to_string(&scalar).expect("Failed in serialization");

        assert_eq!(s, "\"1e240\"");
    }

    #[test]
    fn test_ec_scalar_q() {
        let q: BigInt = Secp256r1Scalar::q();
        assert_eq!(q.to_hex(), "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    }

    #[test]
    fn test_ec_scalar_to_bigint() {
        let hex = "81fe129012fea124ba24091387be0098a1d";
        let scalar: Secp256r1Scalar = ECScalar::from(&BigInt::from_hex(hex));
        assert_eq!(scalar.to_big_int().to_hex(), hex);
    }

    #[test]
    fn test_ec_scalar_new_random() {
        // just checking doesn't crash
        let _scalar = Secp256r1Scalar::new_random();
    }

    #[test]
    fn test_ec_scalar_zero() {
        let scalar = Secp256r1Scalar::zero();
        assert_eq!(scalar.to_big_int().to_hex(), "0");
    }

    #[test]
    fn test_ec_scalar_get_set_element() {
        let mut scalar: Secp256r1Scalar =
            ECScalar::from(&BigInt::from_hex("81fe129012fea124ba24091387be0098a1d"));
        let sk = scalar.get_element();
        assert_eq!(
            format!("{}", sk),
            "0000000000000000000000000000081fe129012fea124ba24091387be0098a1d"
        );

        let new_scalar: Secp256r1Scalar = ECScalar::new_random();
        scalar.set_element(new_scalar.get_element());
        assert_eq!(
            format!("{}", sk),
            "0000000000000000000000000000081fe129012fea124ba24091387be0098a1d"
        );
    }

    #[test]
    fn test_ec_point_generator() {
        let point: Secp256r1Point = ECPoint::generator();
        assert_eq!(
            point.bytes_compressed_to_big_int().to_hex(),
            "36b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        );

        let x = point.x_coor();
        assert!(x.is_some());
        assert_eq!(
            x.unwrap().to_hex(),
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        );

        let y = point.y_coor();
        assert!(y.is_some());
        assert_eq!(
            y.unwrap().to_hex(),
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
    }

    #[test]
    fn test_ec_point_from_bytes() {
        let filename = "src/elliptic/curves/test_vectors/secp256_r1.txt";
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);

        let mut lines_iter = reader.lines().into_iter();
        while let Some(line_res) = lines_iter.next() {
            let mut line = line_res.unwrap(); // Ignore errors.
            if line == "" {
                continue;
            }
            let _k = line.split_off("k = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let x = line.split_off("x = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let y = line.split_off("y = ".len());

            test_ec_point_from_bytes_internal(&x, &y);
        }
    }

    fn test_ec_point_from_bytes_internal(x_hex: &str, y_hex: &str) {
        let x_bi = BigInt::from_hex(x_hex);
        let y_bi = BigInt::from_hex(y_hex);
        let point: Secp256r1Point =
            Secp256r1Point::from_coor(&x_bi, &y_bi);
        assert!(point.x_coor().is_some());
        assert_eq!(
            point.x_coor().unwrap().to_hex(),
            x_bi.to_hex()  // because to_hex() returns unpadded
        );
        assert!(point.y_coor().is_some());
        assert_eq!(
            point.y_coor().unwrap().to_hex(),
            y_bi.to_hex()
        );

        let x_vec = hex::decode(x_hex).unwrap();
        let x_bytes = x_vec.as_slice();
        let y_vec = hex::decode(y_hex).unwrap();
        let y_bytes = y_vec.as_slice();
        let mut bytes = vec![];
        bytes.extend_from_slice(x_bytes);
        bytes.extend_from_slice(y_bytes);
        let point_res =
            Secp256r1Point::from_bytes(bytes.as_slice());
        assert!(point_res.is_ok());
        let point = point_res.unwrap();
        assert_eq!(
            point.x_coor().unwrap().to_hex(),
            x_bi.to_hex()  // because to_hex() returns unpadded
        );
        assert!(point.y_coor().is_some());
        assert_eq!(
            point.y_coor().unwrap().to_hex(),
            y_bi.to_hex()
        );
    }

    #[test]
    #[should_panic]
    fn test_ec_point_from_not_on_curve() {
        let x_bi = BigInt::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let y_bi = BigInt::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F6");
        let _point: Secp256r1Point =
            Secp256r1Point::from_coor(&x_bi, &y_bi);
    }

    #[test]
    fn test_ec_point_get_element() {
        let filename = "src/elliptic/curves/test_vectors/secp256_r1.txt";
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);

        let mut lines_iter = reader.lines().into_iter();
        while let Some(line_res) = lines_iter.next() {
            let mut line = line_res.unwrap(); // Ignore errors.
            if line == "" {
                continue;
            }
            let _k = line.split_off("k = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let x = line.split_off("x = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let y = line.split_off("y = ".len());

            test_ec_point_get_element_internal(&x, &y);
        }
    }

    fn test_ec_point_get_element_internal(x_hex: &str, y_hex: &str) {
        let x_bi = BigInt::from_hex(x_hex);
        let y_bi = BigInt::from_hex(y_hex);
        let point: Secp256r1Point =
            Secp256r1Point::from_coor(&x_bi, &y_bi);
        let pk = point.get_element();

        let copy_point = Secp256r1Point {
            purpose: point.purpose,
            ge: pk,
        };
        assert_eq!(
            format!("{}", point.bytes_compressed_to_big_int().to_hex()),
            format!("{}", copy_point.bytes_compressed_to_big_int().to_hex()),
        );
    }

    #[test]
    fn test_ec_point_pk_to_key_slice() {
        let filename = "src/elliptic/curves/test_vectors/secp256_r1.txt";  // TODO: pull to constant
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);

        let mut lines_iter = reader.lines().into_iter();
        while let Some(line_res) = lines_iter.next() {
            let mut line = line_res.unwrap(); // Ignore errors.
            if line == "" {
                continue;
            }
            let _k = line.split_off("k = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let x = line.split_off("x = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let y = line.split_off("y = ".len());

            test_ec_point_pk_to_key_slice_internal(&x, &y);
        }
    }

    fn test_ec_point_pk_to_key_slice_internal(x_hex: &str, y_hex: &str) {
        let x_bi = BigInt::from_hex(x_hex);
        let y_bi = BigInt::from_hex(y_hex);
        let point: Secp256r1Point =
            Secp256r1Point::from_coor(&x_bi, &y_bi);

        assert_eq!(point.pk_to_key_slice().len(), UNCOMPRESSED_PUBLIC_KEY_SIZE); // uncompressed
        for i in 0..UNCOMPRESSED_PUBLIC_KEY_SIZE {
            assert_eq!(
                point.pk_to_key_slice()[i],
                point.get_element().serialize_uncompressed()[i],
            );
        }
    }

    #[test]
    fn test_ec_point_scalar_mul() {
        let filename = "src/elliptic/curves/test_vectors/secp256_r1.txt";  // TODO: pull to constant
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);

        let mut lines_iter = reader.lines().into_iter();
        while let Some(line_res) = lines_iter.next() {
            let mut line = line_res.unwrap(); // Ignore errors.
            if line == "" {
                continue;
            }
            let k = line.split_off("k = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let x = line.split_off("x = ".len());

            let mut line = lines_iter.next().unwrap().unwrap();
            let y = line.split_off("y = ".len());

            test_ec_point_scalar_mul_internal(&k, &x, &y);
        }
    }

    // test k * G = Q
    fn test_ec_point_scalar_mul_internal(k_dec: &str, x_hex: &str, y_hex: &str) {
        let k_bi: BigInt = BigInt::from_str_radix(k_dec, 10).expect("Error in serialization");
        let x_bi = BigInt::from_hex(x_hex);
        let y_bi = BigInt::from_hex(y_hex);
        let generator: Secp256r1Point = Secp256r1Point::generator();
        let expected: Secp256r1Point = Secp256r1Point::from_coor(&x_bi, &y_bi);
        let scalar: Secp256r1Scalar = ECScalar::from(&k_bi);
        let actual = generator.scalar_mul(&scalar.get_element());

        assert_eq!(
            actual.bytes_compressed_to_big_int().to_hex(),
            expected.bytes_compressed_to_big_int().to_hex(),
        );
    }

    #[test]
    fn test_ec_point_zero_scalar_mul() {
        let zero = Secp256r1Scalar::zero();
        let generator: Secp256r1Point = Secp256r1Point::generator();
        let actual = generator.scalar_mul(&zero.get_element());

        assert_eq!(
            actual.bytes_compressed_to_big_int().to_hex(),
            "20000000000000000000000000000000000000000000000000000000000000000",  // compressed point at infinity
        );
    }

    #[test]
    fn test_ec_point_add_point() {
        let x1_bi = BigInt::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let y1_bi = BigInt::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        let x2_bi = BigInt::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let y2_bi = BigInt::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        let x3_bi = BigInt::from_hex("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978");
        let y3_bi = BigInt::from_hex("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1");

        let point1: Secp256r1Point = Secp256r1Point::from_coor(&x1_bi, &y1_bi);
        let point2: Secp256r1Point = Secp256r1Point::from_coor(&x2_bi, &y2_bi);
        let expected: Secp256r1Point = Secp256r1Point::from_coor(&x3_bi, &y3_bi);
        let actual = point1.add_point(&point2.get_element());

        assert_eq!(
            actual.bytes_compressed_to_big_int().to_hex(),
            expected.bytes_compressed_to_big_int().to_hex(),
        );
    }

    #[test]
    fn test_ec_point_zero_point_add() {
        let zero = Secp256r1Scalar::zero();
        let generator: Secp256r1Point = Secp256r1Point::generator();
        let point_at_infinity = generator.scalar_mul(&zero.get_element());
        let actual = point_at_infinity.add_point(&generator.get_element());

        assert_eq!(
            actual.bytes_compressed_to_big_int().to_hex(),
            generator.bytes_compressed_to_big_int().to_hex(),  // compressed point at infinity
        );
    }

    #[test]
    fn test_ec_point_sub_point() {
        let x1_bi = BigInt::from_hex("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978");
        let y1_bi = BigInt::from_hex("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1");

        let x2_bi = BigInt::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let y2_bi = BigInt::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        let x3_bi = BigInt::from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let y3_bi = BigInt::from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        let point1: Secp256r1Point = Secp256r1Point::from_coor(&x1_bi, &y1_bi);
        let point2: Secp256r1Point = Secp256r1Point::from_coor(&x2_bi, &y2_bi);
        let expected: Secp256r1Point = Secp256r1Point::from_coor(&x3_bi, &y3_bi);
        let actual = point1.sub_point(&point2.get_element());

        assert_eq!(
            actual.bytes_compressed_to_big_int().to_hex(),
            expected.bytes_compressed_to_big_int().to_hex(),
        );
    }

    #[test]
    fn test_ec_point_base_point2() {
        /* show that base_point2() is returning a point which was computed using a deterministic
           algorithm with a (supposedly) random input (the generator's compressed representation) */

        let base_point2 = Secp256r1Point::base_point2();

        let g = Secp256r1Point::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&[&hash]);

        assert_eq!(
            hash,
            base_point2.x_coor().unwrap(),
        );
    }
}
