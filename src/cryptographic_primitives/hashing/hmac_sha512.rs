/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

#![allow(deprecated)]

use crate::BigInt;

use super::traits::KeyedHash;
use crate::arithmetic::traits::*;

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use zeroize::Zeroize;
type HmacSha256type = Hmac<Sha512>;

#[deprecated(since = "0.8.0", note = "use HmacExt instead")]
pub struct HMacSha512;

impl KeyedHash for HMacSha512 {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt {
        let mut key_bytes = key.to_bytes();

        let mut hmac = HmacSha256type::new_from_slice(&key_bytes).expect("");

        for value in data {
            hmac.update(&BigInt::to_bytes(value));
        }
        key_bytes.zeroize();
        let result = hmac.finalize();
        let code = result.into_bytes();

        BigInt::from_bytes(code.as_slice())
    }
    fn verify(key: &BigInt, data: &[&BigInt], code_bytes: [u8; 64]) -> Result<(), ()> {
        let key_bytes = key.to_bytes();

        let mut hmac = HmacSha256type::new_from_slice(&key_bytes).expect("");

        for value in data {
            hmac.update(&BigInt::to_bytes(value));
        }
        match hmac.verify(&code_bytes) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HMacSha512;
    use crate::arithmetic::traits::*;
    use crate::cryptographic_primitives::hashing::traits::KeyedHash;
    use crate::BigInt;

    #[test]
    fn create_hmac_test() {
        let key = BigInt::sample(512);
        let result1 = HMacSha512::create_hmac(&key, &[&BigInt::from(10)]);
        let result1_bytes = &BigInt::to_bytes(&result1)[..];
        let mut array_result: [u8; 64] = [0u8; 64];
        array_result.copy_from_slice(result1_bytes);
        assert!(HMacSha512::verify(&key, &[&BigInt::from(10)], array_result).is_ok());
        let key2 = BigInt::sample(512);
        // same data , different key
        let result2 = HMacSha512::create_hmac(&key2, &[&BigInt::from(10)]);
        assert_ne!(result1, result2);
        // same key , different data
        let result3 = HMacSha512::create_hmac(&key, &[&BigInt::from(10), &BigInt::from(11)]);
        assert_ne!(result1, result3);
        // same key, same data
        let result4 = HMacSha512::create_hmac(&key, &[&BigInt::from(10)]);
        assert_eq!(result1, result4)
    }
}
