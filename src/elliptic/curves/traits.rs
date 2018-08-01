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
use Point;

/// Secret Key Codec: BigInt <> SecretKey
pub trait SecretKeyCodec {
    fn new_random() -> Self;
    fn from_big_int(n: &BigInt) -> Self;

    fn to_big_int(&self) -> BigInt;
    fn get_q() -> BigInt;
}

/// Public Key Codec: Point <> PublicKey
pub trait PublicKeyCodec {
    const KEY_SIZE: usize;
    const HEADER_MARKER: usize;

    fn get_base_point() -> Point;
    fn bytes_compressed_to_big_int(&self) -> BigInt;
    fn to_point(&self) -> Point;

    fn from_key_slice(key: &[u8]) -> Point;
    fn to_key(p: &Point) -> Self;
    fn to_key_slice(p: &Point) -> Vec<u8>;
}
