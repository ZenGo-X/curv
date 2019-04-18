#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// Secp256k1 elliptic curve utility functions (se: https://en.bitcoin.it/wiki/Secp256k1).
//
// In Cryptography utilities, we need to manipulate low level elliptic curve members as Point
// in order to perform operation on them. As the library secp256k1 expose only SecretKey and
// PublicKey, we extend those with simple codecs.
//
// The Secret Key codec: BigInt <> SecretKey
// The Public Key codec: Point <> SecretKey
//

use super::rand::{thread_rng, Rng};
use super::secp256k1::constants::{
    CURVE_ORDER, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
use super::secp256k1::{PublicKey, Secp256k1, SecretKey};
use super::traits::{ECPoint, ECScalar};
use arithmetic::traits::{Converter, Modulo};
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
use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;
use BigInt;
use ErrorKey;

pub type SK = SecretKey;
pub type PK = PublicKey;

#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

impl Secp256k1Point {
    pub fn random_point() -> Secp256k1Point {
        let random_scalar: Secp256k1Scalar = Secp256k1Scalar::new_random();
        let base_point = Secp256k1Point::generator();
        let pk = base_point.scalar_mul(&random_scalar.get_element());
        Secp256k1Point {
            purpose: "random_point",
            ge: pk.get_element(),
        }
    }
    // To generate a random base point we take the hash of the curve generator.
    // This hash creates a random string which do not encode a valid (x,y) curve point.
    // Therefore we continue to hash the result until the first valid point comes out.
    // This function is a result of a manual testing to find
    // this minimal number of hashes and therefore it is written like this.
    // the prefix "2" is to complete for the right parity of the point
    pub fn base_point2() -> Secp256k1Point {
        let g: Secp256k1Point = ECPoint::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&[&hash]);
        let hash = HSha256::create_hash(&[&hash]);
        let mut hash_vec = BigInt::to_vec(&hash);
        let mut template: Vec<u8> = vec![2];
        template.append(&mut hash_vec);
        Secp256k1Point {
            purpose: "random",
            ge: PK::from_slice(&template).unwrap(),
        }
    }
}

impl Zeroize for FE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar<SK> for Secp256k1Scalar {
    fn new_random() -> Secp256k1Scalar {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        Secp256k1Scalar {
            purpose: "random",
            fe: SK::from_slice(&arr[0..arr.len()]).unwrap(),
        }
    }

    fn zero() -> Secp256k1Scalar {
        let zero_arr = [0u8; 32];
        let zero = unsafe { std::mem::transmute::<[u8; 32], SecretKey>(zero_arr) };
        Secp256k1Scalar {
            purpose: "zero",
            fe: zero,
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }

    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Secp256k1Scalar {
        let curve_order = FE::q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0), &curve_order);
        let mut v = BigInt::to_vec(&n_reduced);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }

        Secp256k1Scalar {
            purpose: "from_big_int",
            fe: SK::from_slice(&v).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(&(self.fe[0..self.fe.len()]))
    }

    fn q() -> BigInt {
        BigInt::from(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_add(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "add",
            fe: res.get_element(),
        }
    }

    fn mul(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_mul(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "mul",
            fe: res.get_element(),
        }
    }

    fn sub(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_sub(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "sub",
            fe: res.get_element(),
        }
    }

    fn invert(&self) -> Secp256k1Scalar {
        let bignum = self.to_big_int();
        let bn_inv = bignum.invert(&FE::q()).unwrap();
        ECScalar::from(&bn_inv)
    }
}
impl Mul<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for Secp256k1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Secp256k1Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Secp256k1Scalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Secp256k1Scalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl PartialEq for Secp256k1Point {
    fn eq(&self, other: &Secp256k1Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for GE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint<PK, SK> for Secp256k1Point {
    fn generator() -> Secp256k1Point {
        let mut v = vec![4 as u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        Secp256k1Point {
            purpose: "base_fe",
            ge: PK::from_slice(&v).unwrap(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    /// to return from BigInt to PK use from_bytes:
    /// 1) convert BigInt::to_vec
    /// 2) remove first byte [1..33]
    /// 3) call from_bytes
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let serial = self.ge.serialize();
        BigInt::from(&serial[0..33])
    }

    fn x_coor(&self) -> Option<BigInt> {
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
        let x_vec = x.to_vec();
        Some(BigInt::from(&x_vec[..]))
    }

    fn y_coor(&self) -> Option<BigInt> {
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
        let y_vec = y.to_vec();
        Some(BigInt::from(&y_vec[..]))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Secp256k1Point, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_65 = [0u8; 65];
        let mut bytes_array_33 = [0u8; 33];

        let byte_len = bytes_vec.len();
        match byte_len {
            33...63 => {
                let mut template = vec![0; 64 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec.clone());
                let mut bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);
                let result = PK::from_slice(&bytes_array_65);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }

            0...32 => {
                let mut template = vec![0; 32 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let mut rng = rand::thread_rng();
                let bit: bool = rng.gen();
                println!("rand {:?}", 2 + bit as u8);
                let mut template: Vec<u8> = vec![2 + bit as u8];
                template.append(&mut bytes_vec.clone());
                let mut bytes_slice = &template[..];

                bytes_array_33.copy_from_slice(&bytes_slice[0..33]);
                let result = PK::from_slice(&bytes_array_33);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }
            _ => {
                let bytes_slice = &bytes_vec[0..64];
                let bytes_vec = bytes_slice.to_vec();
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec.clone());
                let mut bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);
                let result = PK::from_slice(&bytes_array_65);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }
        }
    }
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut v = vec![4 as u8];

        v.extend(BigInt::to_vec(&self.x_coor().unwrap()));
        v.extend(BigInt::to_vec(&self.y_coor().unwrap()));
        v
    }

    fn scalar_mul(&self, fe: &SK) -> Secp256k1Point {
        let mut new_point = *self;
        new_point
            .ge
            .mul_assign(&Secp256k1::new(), &fe[..])
            .expect("Assignment expected");
        new_point
    }

    fn add_point(&self, other: &PK) -> Secp256k1Point {
        Secp256k1Point {
            purpose: "combine",
            ge: self.ge.combine(other).unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Secp256k1Point {
        let point = Secp256k1Point {
            purpose: "sub_point",
            ge: *other,
        };
        let p: Vec<u8> = vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
        ];
        let order = BigInt::from(&p[..]);
        let x = point.x_coor().unwrap();
        let y = point.y_coor().unwrap();
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

        let minus_point: GE = ECPoint::from_bytes(&x_vec).unwrap();
        //let minus_point: GE = ECPoint::from_coor(&x, &y_inv);
        ECPoint::add_point(self, &minus_point.get_element())
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Secp256k1Point {
        let mut vec_x = BigInt::to_vec(x);
        let mut vec_y = BigInt::to_vec(y);
        let coor_size = (UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) / 2;

        if vec_x.len() < coor_size {
            // pad
            let mut x_buffer = vec![0; coor_size - vec_x.len()];
            x_buffer.extend_from_slice(&vec_x);
            vec_x = x_buffer
        }

        if vec_y.len() < coor_size {
            // pad
            let mut y_buffer = vec![0; coor_size - vec_y.len()];
            y_buffer.extend_from_slice(&vec_y);
            vec_y = y_buffer
        }

        assert_eq!(x, &BigInt::from(vec_x.as_ref()));
        assert_eq!(y, &BigInt::from(vec_y.as_ref()));

        let mut v = vec![4 as u8];
        v.extend(vec_x);
        v.extend(vec_y);

        Secp256k1Point {
            purpose: "base_fe",
            ge: PK::from_slice(&v).unwrap(),
        }
    }
}

impl Hashable for Secp256k1Point {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.update(&bytes);
    }
}

impl Mul<Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl Serialize for Secp256k1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.x_coor().unwrap().to_hex())?;
        state.serialize_field("y", &self.y_coor().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Secp256k1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = &["x", "y"];
        deserializer.deserialize_struct("Secp256k1Point", fields, Secp256k1PointVisitor)
    }
}

struct Secp256k1PointVisitor;

impl<'de> Visitor<'de> for Secp256k1PointVisitor {
    type Value = Secp256k1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Point")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Secp256k1Point, E::Error> {
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

        Ok(Secp256k1Point::from_coor(&bx, &by))
    }
}
#[cfg(feature = "curvesecp256k1")]
#[cfg(test)]
mod tests {
    use super::BigInt;
    use super::Secp256k1Point;
    use super::Secp256k1Scalar;
    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use cryptographic_primitives::hashing::hash_sha256::HSha256;
    use cryptographic_primitives::hashing::traits::Hash;
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use serde_json;

    #[test]
    fn serialize_sk() {
        let scalar: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));
        let s = serde_json::to_string(&scalar).expect("Failed in serialization");
        assert_eq!(s, "\"1e240\"");
    }

    #[test]
    fn serialize_rand_pk_verify_pad() {
        let vx = BigInt::from_hex(
            &"ccaf75ab7960a01eb421c0e2705f6e84585bd0a094eb6af928c892a4a2912508".to_string(),
        );

        let vy = BigInt::from_hex(
            &"e788e294bd64eee6a73d2fc966897a31eb370b7e8e9393b0d8f4f820b48048df".to_string(),
        );

        Secp256k1Point::from_coor(&vx, &vy); // x and y of size 32

        let x = BigInt::from_hex(
            &"5f6853305467a385b56a5d87f382abb52d10835a365ec265ce510e04b3c3366f".to_string(),
        );

        let y = BigInt::from_hex(
            &"b868891567ca1ee8c44706c0dc190dd7779fe6f9b92ced909ad870800451e3".to_string(),
        );

        Secp256k1Point::from_coor(&x, &y); // x and y not of size 32 each

        let r = Secp256k1Point::random_point();
        let r_expected = Secp256k1Point::from_coor(&r.x_coor().unwrap(), &r.y_coor().unwrap());

        assert_eq!(r.x_coor().unwrap(), r_expected.x_coor().unwrap());
        assert_eq!(r.y_coor().unwrap(), r_expected.y_coor().unwrap());
    }

    #[test]
    fn deserialize_sk() {
        let s = "\"1e240\"";
        let dummy: Secp256k1Scalar = serde_json::from_str(s).expect("Failed in serialization");

        let sk: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));

        assert_eq!(dummy, sk);
    }

    #[test]
    fn serialize_pk() {
        let pk = Secp256k1Point::generator();
        let x = pk.x_coor().unwrap();
        let y = pk.y_coor().unwrap();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");

        let expected = format!("{{\"x\":\"{}\",\"y\":\"{}\"}}", x.to_hex(), y.to_hex());
        assert_eq!(s, expected);

        let des_pk: Secp256k1Point = serde_json::from_str(&s).expect("Failed in serialization");
        assert_eq!(des_pk.ge, pk.ge);
    }

    use elliptic::curves::secp256_k1::{FE, GE};
    use ErrorKey;

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
    #[should_panic]
    fn test_serdes_bad_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        let s: String = s.replace("79be", "79bf");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

    #[test]
    fn test_from_bytes() {
        let g = Secp256k1Point::generator();
        let hash = HSha256::create_hash(&vec![&g.bytes_compressed_to_big_int()]);
        let hash_vec = BigInt::to_vec(&hash);
        let result = Secp256k1Point::from_bytes(&hash_vec);
        assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey)
    }

    #[test]
    fn test_from_bytes_2() {
        let g: Secp256k1Point = ECPoint::generator();
        let hash = HSha256::create_hash(&vec![&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(&vec![&hash]);
        let hash = HSha256::create_hash(&vec![&hash]);
        let hash_vec = BigInt::to_vec(&hash);
        let result = Secp256k1Point::from_bytes(&hash_vec);
        let ground_truth = Secp256k1Point::base_point2();
        assert_eq!(result.unwrap(), ground_truth);
    }
    #[test]
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256k1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_from_bytes_4() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256k1Point::from_bytes(&test_vec);
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
        let result = Secp256k1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

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
        let point_ab1 = base.clone() * a_minus_b_fe;

        let point_a = base.clone() * a;
        let point_b = base.clone() * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1.get_element(), point_ab2.get_element());
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
    fn test_scalar_mul_scalar() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let c1 = a.mul(&b.get_element());
        let c2 = a * b;
        assert_eq!(c1.get_element(), c2.get_element());
    }

}
