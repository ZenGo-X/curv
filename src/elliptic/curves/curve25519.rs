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

use super::rand::thread_rng;
use super::curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use super::curve25519_dalek::constants::BASEPOINT_ORDER;
use super::curve25519_dalek::scalar::Scalar;
use super::curve25519_dalek::constants;
use super::curve25519_dalek::edwards::CompressedEdwardsY;
use super::curve25519_dalek::edwards::EdwardsPoint;
//use super::curve25519_dalek::field::FieldElement64;
use super::traits::{ECPoint, ECScalar};
pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;


pub type SK = Scalar;
pub type PK = CompressedEdwardsY;

#[derive(Clone, PartialEq, Debug)]
pub struct Curve25519Scalar{
    purpose: &'static str,
    fe: SK
}
#[derive(Clone, PartialEq, Debug)]
pub struct Curve25519Point{
    purpose: &'static str,
    ge: PK
}
pub type GE = Curve25519Point;
pub type FE = Curve25519Scalar;

impl ECScalar<SK> for Curve25519Scalar{

    fn new_random() -> Curve25519Scalar {
        //let mut csprng: OsRng = OsRng::new().unwrap();
        Curve25519Scalar {
            purpose : "random",
             fe: SK::random(&mut thread_rng())
        }
    }

    fn get_element(&self) -> SK{
        self.fe
    }
    fn set_element(&mut self, element: SK) {self.fe = element}

    fn from_big_int(n: &BigInt) -> Curve25519Scalar {
        let mut v = BigInt::to_vec(n);
        //TODO: add consistency check for sizes max 32/ max 64
        let mut bytes_array_32: [u8;32];
        let mut bytes_array_64: [u8;64];
        if v.len()<=SECRET_KEY_SIZE {
            bytes_array_32 = [0; SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_32.copy_from_slice(&bytes);
            Curve25519Scalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order(bytes_array_32)
            }
        }
        else{
            bytes_array_64 = [0; 2*SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_64.copy_from_slice(&bytes);
            Curve25519Scalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order_wide(&bytes_array_64)
            }
        }

    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(&(self.fe.to_bytes()[0..self.fe.to_bytes().len()]))
    }


    fn get_q(&self) -> BigInt {
        BigInt::from(BASEPOINT_ORDER.to_bytes()[0..BASEPOINT_ORDER.to_bytes().len()].as_ref())
    }

    fn add(&self, other: &SK) -> Curve25519Scalar{
        Curve25519Scalar {
            purpose : "add",
            fe: &self.get_element() + other
        }
    }

    fn mul(&self, other: &SK) -> Curve25519Scalar{
        Curve25519Scalar {
            purpose : "mul",
            fe: &self.get_element() * other
        }
    }

    fn sub(&self, other: &SK) -> Curve25519Scalar{
        Curve25519Scalar {
            purpose : "mul",
            fe: &self.get_element() - other
        }
    }
}


impl ECPoint<PK,SK> for Curve25519Point{

    fn new() -> Curve25519Point {
        Curve25519Point{
            purpose: "base_fe",
            ge: constants::ED25519_BASEPOINT_COMPRESSED
        }
    }

    fn get_element(&self) -> PK{
        self.ge
    }


    fn get_x_coor_as_big_int(&self) -> BigInt{
        /* taken from https://doc-internal.dalek.rs/src/curve25519_dalek/edwards.rs.html#144
        let y = self.ge.as_bytes().clone();
        let Y = SK::from_bytes_mod_order(y);
        let Z = SK::one();
        let YY = Y*Y;
        let u = &YY - &Z;
        let v = &(&YY * &constants::EDWARDS_D) + &Z;
        let (is_nonzero_square, mut X) = sqrt_ratio(&u, &v);
        */
        //TODO: find a way to return x-coor
        let field_y = self.ge.as_bytes();
        BigInt::from(field_y[0..field_y.len()].as_ref())
    }

    fn get_y_coor_as_big_int(&self) -> BigInt{
        let field_y = self.ge.as_bytes();
        BigInt::from(field_y[0..field_y.len()].as_ref())
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt{
        BigInt::from(self.ge.to_bytes()[0..self.ge.to_bytes().len()].as_ref())
    }
/*
    fn from_key_slice(key: &[u8]) -> Curve25519Point{
        assert_eq!(key.len(), COOR_BYTE_SIZE*4);
        let mut array : [u8;32] = [0; 32];
        // first 32 elements (without the header)
        // let q1_end_index = COOR_BYTE_SIZE;
        // let q2_end_index = 2*COOR_BYTE_SIZE;
        // let q3_end_index = 3*COOR_BYTE_SIZE;
        // let q4_end_index = key.len();
        // array.copy_from_slice(&key[0..q1_end_index]);
        // let X  = FieldElement64::from_bytes(&array);
        // array.copy_from_slice(&key[q1_end_index..q2_end_index]);
        // let Y  = FieldElement64::from_bytes(&array);
        // array.copy_from_slice(&key[q2_end_index..q3_end_index]);
        // let Z = FieldElement64::from_bytes(&array);
        // array.copy_from_slice(&key[q3_end_index..q4_end_index]);
        // let T = FieldElement64::from_bytes(&array);
        // EdwardsPoint{X,Y,Z,T}.compress()
        // TODO: add a test if point (x,y) is on curve.
        array.copy_from_slice(key);
        Curve25519Point{
            purpose: "from_key_slice",
            ge: CompressedEdwardsY(array)
        }
    }
*/

    fn pk_to_key_slice(&self) -> Vec<u8>{
        let result = self.ge.to_bytes();
        result.to_vec()
    }

    fn scalar_mul(mut self, fe: &SK) -> Curve25519Point{
        let skpk = fe * (self.ge.decompress().unwrap());
        Curve25519Point{
            purpose: "scalar_point_mul",
            ge: skpk.compress()
        }
    }


    fn add_point(&self, other: &PK) -> Curve25519Point{
        let pkpk =  self.ge.decompress().unwrap() + other.decompress().unwrap();
        Curve25519Point{
            purpose: "combine",
            ge: pkpk.compress()
        }

    }

}





