/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use crate::BigInt;
use crate::{FE, GE};

pub trait Hash {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt;
    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE;
}

pub trait KeyedHash {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt;
    fn verify(key: &BigInt, data: &[&BigInt], code_bytes: [u8; 64]) -> Result<(), ()>;
}
