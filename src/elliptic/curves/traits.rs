/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::ops::{Add, Mul};

use crate::BigInt;
use crate::ErrorKey;

pub trait ECScalar: Mul<Output=Self> + Add<Output=Self> + Sized {
    type SecretKey;

    fn new_random() -> Self;
    fn zero() -> Self;
    fn get_element(&self) -> Self::SecretKey;
    fn set_element(&mut self, element: Self::SecretKey);
    fn from(n: &BigInt) -> Self;
    fn to_big_int(&self) -> BigInt;
    fn q() -> BigInt;
    fn add(&self, other: &Self::SecretKey) -> Self;
    fn mul(&self, other: &Self::SecretKey) -> Self;
    fn sub(&self, other: &Self::SecretKey) -> Self;
    fn invert(&self) -> Self;
}

// TODO: add a fn is_point
pub trait ECPoint: Mul<<Self as ECPoint>::Scalar, Output=Self> + Add<Output = Self>
where
    Self: Sized,
{
    type SecretKey;
    type PublicKey;

    type Scalar: ECScalar<SecretKey = Self::SecretKey>;

    fn base_point2() -> Self;
    fn generator() -> Self;
    fn get_element(&self) -> Self::PublicKey;
    fn x_coor(&self) -> Option<BigInt>;
    fn y_coor(&self) -> Option<BigInt>;
    fn bytes_compressed_to_big_int(&self) -> BigInt;
    fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorKey>;
    fn pk_to_key_slice(&self) -> Vec<u8>;
    fn scalar_mul(&self, fe: &Self::SecretKey) -> Self;
    fn add_point(&self, other: &Self::PublicKey) -> Self;
    fn sub_point(&self, other: &Self::PublicKey) -> Self;
    fn from_coor(x: &BigInt, y: &BigInt) -> Self;
}
