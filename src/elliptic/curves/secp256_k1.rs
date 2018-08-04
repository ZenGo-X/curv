/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
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
use BigInt;

use arithmetic::traits::Converter;

use super::rand::{thread_rng, Rng};

use super::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE};
use super::secp256k1::{PublicKey, Secp256k1, SecretKey};
use super::traits::{ECPoint, ECScalar};

pub type EC = Secp256k1;
pub type SK = SecretKey;
pub type PK = PublicKey;


#[derive(Clone, PartialEq, Debug)]
pub struct Secp256k1Scalar{
    purpose: &'static str,
    fe: SK
}
#[derive(Clone, PartialEq, Debug)]
pub struct Secp256k1Point{
    purpose: &'static str,
    ge: PK
}
pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

impl ECScalar<SK> for Secp256k1Scalar{
    fn new_random() -> Secp256k1Scalar {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        Secp256k1Scalar {
            purpose : "random",
            //fe: SK::new( & EC::without_caps(), &mut csprng)
            fe: SK::from_slice(&EC::without_caps(), &arr[0..arr.len()]).unwrap()
           // fe: SK::new( & EC::without_caps(), &mut thread_rng())
         }
    }

    fn get_element(&self) -> SK{
        self.fe
    }

    fn from_big_int(n: &BigInt) -> Secp256k1Scalar {
        let mut v = BigInt::to_vec(n);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        Secp256k1Scalar {
        purpose: "from_big_int",
        fe: SK::from_slice( & EC::without_caps(), &v).unwrap()
        }
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(&(self.fe[0..self.fe.len()]))
    }

    fn get_q(&self) -> BigInt {
        BigInt::from(CURVE_ORDER.as_ref())
    }
}


impl ECPoint<PK,SK> for Secp256k1Point{
    fn new() -> Secp256k1Point {
        let mut v = vec![4 as u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        Secp256k1Point{
            purpose: "base_fe",
            ge: PK::from_slice(&Secp256k1::without_caps(), &v).unwrap()
        }
    }

    fn get_element(&self) -> PK{
        self.ge
    }

    fn get_x_coor_as_big_int(&self) -> BigInt{
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
        BigInt::from(x)
    }

    fn get_y_coor_as_big_int(&self) -> BigInt{
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
        BigInt::from(y)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt{
        let serial = self.ge.serialize();
        let result = BigInt::from(&serial[0..33]);
        return result;
    }


    fn from_key_slice(key: &[u8]) -> Secp256k1Point{
        assert_eq!(key.len(), 32);
        let header = key[0] as usize;
        assert_eq!(header, 4);

        // first 32 elements (without the header)
        let x = &key[1..key.len() / 2 + 1];
        // last 32 element
        let y = &key[(key.len() - 1) / 2 + 1..key.len()];
        let y_coord_size = 32;
        let y_zeros_vec = vec![0; y_coord_size];
        assert_ne!(y, &y_zeros_vec[..]);
        // TODO: add a test if point (x,y) is on curve.
        Secp256k1Point{
            purpose: "from_key_slice",
            ge: PK::from_slice(&EC::without_caps(), &key).unwrap()
        }
    }

    fn pk_to_key_slice(&self) -> Vec<u8>{
        let mut v = vec![4 as u8];

        v.extend(BigInt::to_vec(&self.get_x_coor_as_big_int()));
        v.extend(BigInt::to_vec(&self.get_y_coor_as_big_int()));
        v
    }

    fn scalar_mul(mut self, fe: &SK) -> Secp256k1Point{
        self.ge.mul_assign(&EC::new(), fe).expect("Assignment expected");
        self
     //   Secp256k1Point{
    //        purpose: "mul_assign",
     //       ge: pubkey
    //    }
    }
    fn add_point(&self, other: &PK) -> Secp256k1Point{
        Secp256k1Point{
            purpose: "combine",
            ge: self.ge.combine(&EC::new(), other).unwrap()
        }
    }

}


#[cfg(test)]
mod tests {
    /*
    use super::{PublicKeyCodec, SecretKeyCodec};

    use elliptic::curves::rand::thread_rng;
    use elliptic::curves::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y};
    use elliptic::curves::secp256k1::{PublicKey, Secp256k1, SecretKey};

    use BigInt;
    use super::Point;
    use super::RawPoint;

    use serde_json;

    #[test]
    fn equality_test() {
        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };
        let p2 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };
        assert_eq!(p1, p2);

        let p3 = Point {
            x: BigInt::zero(),
            y: BigInt::one(),
        };
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_serialization() {
        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };

        let s = serde_json::to_string(&RawPoint::from(p1)).expect("Failed in serialization");
        assert_eq!(s, "{\"x\":\"1\",\"y\":\"0\"}");
    }

    #[test]
    fn test_deserialization() {
        let sp1 = "{\"x\":\"1\",\"y\":\"0\"}";
        let rp1: RawPoint = serde_json::from_str(&sp1).expect("Failed in serialization");

        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };

        assert_eq!(rp1, RawPoint::from(p1));
    }


    #[test]
    fn get_base_point_test() {
        let p = PublicKey::get_base_point();

        assert_eq!(p.x, BigInt::from(GENERATOR_X.as_ref()));
        assert_eq!(p.y, BigInt::from(GENERATOR_Y.as_ref()));
    }

    #[test]
    fn get_q_test() {
        let q = SecretKey::get_q();

        assert_eq!(q, BigInt::from(CURVE_ORDER.as_ref()));
    }

    #[test]
    fn from_secret_key_to_big_int() {
        let sk = SecretKey::new(&Secp256k1::without_caps(), &mut thread_rng());

        let sk_n = sk.to_big_int();
        let sk_back = SecretKey::from_big_int(&sk_n);

        assert_eq!(sk, sk_back);
    }

    #[test]
    #[should_panic]
    #[cfg_attr(rustfmt, rustfmt_skip)] // ignore fmt due to the slice comments
    fn from_invalid_header_key_slice_test() {
        let invalid_key: [u8; PublicKey::KEY_SIZE] = [
            1, // header
            // X
            231, 191, 194, 227, 183, 188, 238, 170, 206, 138, 20, 92, 140, 107, 83, 73,
            111, 170, 217, 69, 17, 64, 121, 65, 219, 97, 147, 181, 197, 239, 158, 56,
            // Y
            62, 15, 115, 56, 226, 122, 3, 180, 192, 166, 171, 137, 121, 23, 29, 225, 234, 220, 154,
            2, 157, 44, 73, 220, 31, 15, 55, 4, 244, 189, 7, 210,
        ];

        PublicKey::from_key_slice(&invalid_key);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)] // ignore fmt due to the slice comments
    fn from_valid_uncompressed_key_slice_to_key_test() {
        let valid_key: [u8; PublicKey::KEY_SIZE] = [
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85,
            220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179,
            // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let p = PublicKey::from_key_slice(&valid_key);
        let k = PublicKey::to_key_slice(&p);
        assert_eq!(valid_key.len(), k.len());

        for (i, _elem) in k.iter().enumerate() {
            assert_eq!(valid_key[i], k[i]);
        }
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)] // ignore fmt due to the slice comments
    fn from_public_key_to_point_to_slice_to_key() {
        let slice = &[
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85,
            220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179,
            // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let uncompressed_key = PublicKey::from_slice(
            &Secp256k1::without_caps(), slice).unwrap();
        let p = uncompressed_key.to_point();
        let key_slice = PublicKey::to_key_slice(&p);

        assert_eq!(slice.len(), key_slice.len());

        for (i, _elem) in key_slice.iter().enumerate() {
            assert_eq!(slice[i], key_slice[i]);
        }

        let expected_key = PublicKey::to_key(&p);
        assert_eq!(expected_key, uncompressed_key);
    }
    */
}
