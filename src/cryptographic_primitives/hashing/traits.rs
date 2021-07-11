/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use crate::elliptic::curves::{Curve, Point, PointZ, ScalarZ};
use crate::BigInt;

#[deprecated(since = "0.8.0", note = "use DigestExt instead")]
pub trait Hash {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt;
    fn create_hash_from_slice(byte_slice: &[u8]) -> BigInt;
    fn create_hash_from_ge<E: Curve>(ge_vec: &[&Point<E>]) -> ScalarZ<E>;
    fn create_hash_from_ge_z<E: Curve>(ge_vec: &[&PointZ<E>]) -> ScalarZ<E>;
}

#[deprecated(since = "0.8.0", note = "use HmacExt instead")]
pub trait KeyedHash {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt;
    #[allow(clippy::result_unit_err)]
    fn verify(key: &BigInt, data: &[&BigInt], code_bytes: [u8; 64]) -> Result<(), ()>;
}
