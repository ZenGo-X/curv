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

use super::traits::Hash;
use arithmetic::traits::Converter;
use ring::digest::{Context, SHA512};

pub struct HSha512;

impl Hash for HSha512 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut digest = Context::new(&SHA512);

        for value in big_ints {
            digest.update(&BigInt::to_vec(value));
        }

        BigInt::from(digest.finish().as_ref())
    }
}
