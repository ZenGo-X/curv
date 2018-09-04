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

use super::traits::KeyedHash;
use arithmetic::traits::Converter;
use ring::{digest, hmac};

pub struct HMacSha512;

impl KeyedHash for HMacSha512 {
    fn create_hmac(key: &BigInt, data: Vec<&BigInt>) -> BigInt {
        let key_bytes: Vec<u8> = key.into();
        let s_key = hmac::SigningKey::new(&digest::SHA512, &key_bytes);
        let mut s_ctx = hmac::SigningContext::with_key(&s_key);

        for value in data {
            s_ctx.update(&BigInt::to_vec(&value));
        }

        BigInt::from(s_ctx.sign().as_ref())
    }
}

#[cfg(test)]
mod tests {

    use super::HMacSha512;
    use arithmetic::traits::Samplable;
    use cryptographic_primitives::hashing::traits::KeyedHash;
    use BigInt;

    #[test]
    fn create_hmac_test() {
        let key = BigInt::sample(512);
        let result = HMacSha512::create_hmac(&key, vec![&BigInt::from(10)]);
        println!("HMAC: {:?}", result.to_str_radix(16));
    }
}
