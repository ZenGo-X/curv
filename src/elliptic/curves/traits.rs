/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use BigInt;
use ErrorKey;

pub trait ECScalar<SK> {
    fn new_random() -> Self;
    fn zero() -> Self;
    fn get_element(&self) -> SK;
    fn set_element(&mut self, element: SK);
    fn from(n: &BigInt) -> Self;
    fn to_big_int(&self) -> BigInt;
    fn q() -> BigInt;
    fn add(&self, other: &SK) -> Self;
    fn mul(&self, other: &SK) -> Self;
    fn sub(&self, other: &SK) -> Self;
    fn invert(&self) -> Self;
}

// TODO: add a fn is_point
pub trait ECPoint<PK, SK>
where
    Self: Sized,
{
    fn generator() -> Self;
    fn get_element(&self) -> PK;
    fn x_coor(&self) -> Option<BigInt>;
    fn y_coor(&self) -> Option<BigInt>;
    fn bytes_compressed_to_big_int(&self) -> BigInt;
    fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorKey>;
    fn pk_to_key_slice(&self) -> Vec<u8>;
    fn scalar_mul(&self, fe: &SK) -> Self;
    fn add_point(&self, other: &PK) -> Self;
    fn sub_point(&self, other: &PK) -> Self;
    fn from_coor(x: &BigInt, y: &BigInt) -> Self;
}
