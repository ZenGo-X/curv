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

use super::rand::{thread_rng, Rng};
use super::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE};
use super::secp256k1::{None, PublicKey, Secp256k1, SecretKey};
use super::traits::{ECPoint, ECScalar};
use arithmetic::traits::{Converter, Modulo};
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

pub type EC = Secp256k1<None>;
pub type SK = SecretKey;
pub type PK = PublicKey;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Secp256k1Scalar {
    purpose: String, // it has to be a non constant string for serialization
    fe: SK,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Secp256k1Point {
    purpose: String, // it has to be a non constant string for serialization
    ge: PK,
}
pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

impl Secp256k1Point {
    pub fn random_point() -> Secp256k1Point {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        Secp256k1Point {
            purpose: "blind_point".to_string(),
            ge: PK::from_slice(&EC::without_caps(), &arr[0..arr.len()]).unwrap(),
        }
    }
    //TODO: implement for other curves
    //TODO: make constant
    pub fn base_point2() -> Secp256k1Point {
        let g: Secp256k1Point = ECPoint::new();
        let hash = HSha256::create_hash(vec![&g.bytes_compressed_to_big_int()]);
        let hash = HSha256::create_hash(vec![&hash]);
        let hash = HSha256::create_hash(vec![&hash]);
        let mut hash_vec = BigInt::to_vec(&hash);
        let mut template: Vec<u8> = vec![2];
        template.append(&mut hash_vec);

        Secp256k1Point {
            purpose: "blind_point".to_string(),
            ge: PK::from_slice(&EC::without_caps(), &template).unwrap(),
        }
    }
}

impl ECScalar<SK> for Secp256k1Scalar {
    fn new_random() -> Secp256k1Scalar {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        Secp256k1Scalar {
            purpose: "random".to_string(),
            //fe: SK::new( & EC::without_caps(), &mut csprng)
            fe: SK::from_slice(&EC::without_caps(), &arr[0..arr.len()]).unwrap(), // fe: SK::new( & EC::without_caps(), &mut thread_rng())
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }

    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from_big_int(n: &BigInt) -> Secp256k1Scalar {
        let temp_fe: FE = ECScalar::new_random();
        let curve_order = temp_fe.get_q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0), &curve_order);
        let mut v = BigInt::to_vec(&n_reduced);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        Secp256k1Scalar {
            purpose: "from_big_int".to_string(),
            fe: SK::from_slice(&EC::without_caps(), &v).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(&(self.fe[0..self.fe.len()]))
    }

    fn get_q(&self) -> BigInt {
        BigInt::from(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from_big_int(&BigInt::mod_add(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &self.get_q(),
        ));
        Secp256k1Scalar {
            purpose: "add".to_string(),
            fe: res.get_element(),
        }
    }

    fn mul(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from_big_int(&BigInt::mod_mul(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &self.get_q(),
        ));
        Secp256k1Scalar {
            purpose: "mul".to_string(),
            fe: res.get_element(),
        }
    }

    fn sub(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from_big_int(&BigInt::mod_sub(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &self.get_q(),
        ));
        Secp256k1Scalar {
            purpose: "mul".to_string(),
            fe: res.get_element(),
        }
    }
}

impl ECPoint<PK, SK> for Secp256k1Point {
    fn new() -> Secp256k1Point {
        let mut v = vec![4 as u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        Secp256k1Point {
            purpose: "base_fe".to_string(),
            ge: PK::from_slice(&Secp256k1::without_caps(), &v).unwrap(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn get_x_coor_as_big_int(&self) -> BigInt {
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
        BigInt::from(x)
    }

    fn get_y_coor_as_big_int(&self) -> BigInt {
        let serialized_pk = PK::serialize_uncompressed(&self.ge);
        let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
        BigInt::from(y)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let serial = self.ge.serialize();
        let result = BigInt::from(&serial[0..33]);
        return result;
    }

    /*
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
*/
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut v = vec![4 as u8];

        v.extend(BigInt::to_vec(&self.get_x_coor_as_big_int()));
        v.extend(BigInt::to_vec(&self.get_y_coor_as_big_int()));
        v
    }

    fn scalar_mul(mut self, fe: &SK) -> Secp256k1Point {
        self.ge
            .mul_assign(&Secp256k1::new(), fe) // we can't use Secp256k1 <None> (EC) in mul_assign
            .expect("Assignment expected");
        self
        //   Secp256k1Point{
        //        purpose: "mul_assign",
        //       ge: pubkey
        //    }
    }
    fn add_point(&self, other: &PK) -> Secp256k1Point {
        Secp256k1Point {
            purpose: "combine".to_string(),
            ge: self.ge.combine(&EC::without_caps(), other).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use BigInt;

    use arithmetic::traits::{Converter, Modulo};

    use super::ECPoint;
    use super::ECScalar;
    use super::FE;
    use serde_json;

    /*
    #[test]
    fn test_from_big_int(){
        let temp: FE = ECScalar::new_random();
        let co = temp.get_q();
        let temp2: FE = ECScalar::from_big_int(&co);

    }*/
}
