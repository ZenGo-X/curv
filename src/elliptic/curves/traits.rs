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

use BigInt;

pub trait ECScalar<SK> {
    fn new_random() -> Self;
    fn get_element(&self) -> SK;
    fn set_element(&mut self, element: SK);
    fn from(n: &BigInt) -> Self;
    fn to_big_int(&self) -> BigInt;
    fn q(&self) -> BigInt;
    fn add(&self, other: &SK) -> Self;
    fn mul(&self, other: &SK) -> Self;
    fn sub(&self, other: &SK) -> Self;
}

// TODO: add a fn is_point
pub trait ECPoint<PK, SK> {
    fn generator() -> Self;
    fn get_element(&self) -> PK;
    fn x_coor(&self) -> BigInt;
    fn y_coor(&self) -> BigInt;
    fn bytes_compressed_to_big_int(&self) -> BigInt;
    //fn from_key_slice(key: &[u8]) -> Self;
    fn pk_to_key_slice(&self) -> Vec<u8>;
    fn scalar_mul(self, fe: &SK) -> Self;
    fn add_point(&self, other: &PK) -> Self;
    fn from_coor(x: &BigInt, y: &BigInt) -> Self;
}
