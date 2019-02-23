/*
    Curv

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/
use BigInt;

use super::traits::KeyedHash;
use arithmetic::traits::Converter;
use ring::{digest, hmac};
use zeroize::Zeroize;
pub struct HMacSha512;

impl KeyedHash for HMacSha512 {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt {
        let mut key_bytes: Vec<u8> = key.into();
        let mut s_ctx =
            hmac::SigningContext::with_key(&hmac::SigningKey::new(&digest::SHA512, &key_bytes));

        for value in data {
            s_ctx.update(&BigInt::to_vec(value));
        }
        key_bytes.zeroize();
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
        let result1 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10)]);
        let key2 = BigInt::sample(512);
        // same data , different key
        let result2 = HMacSha512::create_hmac(&key2, &vec![&BigInt::from(10)]);
        assert_ne!(result1, result2);
        // same key , different data
        let result3 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10), &BigInt::from(11)]);
        assert_ne!(result1, result3);
        // same key, same data
        let result4 = HMacSha512::create_hmac(&key, &vec![&BigInt::from(10)]);
        assert_eq!(result1, result4)
    }
}
