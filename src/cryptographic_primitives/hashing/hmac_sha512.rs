/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use crate::BigInt;

use super::traits::KeyedHash;
use crate::arithmetic::traits::Converter;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha512;
use zeroize::Zeroize;

pub struct HMacSha512;

impl KeyedHash for HMacSha512 {
    fn create_hmac(key: &BigInt, data: &[&BigInt]) -> BigInt {
        let mut key_bytes: Vec<u8> = key.into();
        let mut hmac = Hmac::new(Sha512::new(), &key_bytes);

        for value in data {
            hmac.input(&BigInt::to_vec(value));
        }
        key_bytes.zeroize();
        let result = hmac.result();
        let code = result.code();

        BigInt::from(code)
    }
}

#[cfg(test)]
mod tests {

    use super::HMacSha512;
    use crate::arithmetic::traits::Samplable;
    use crate::cryptographic_primitives::hashing::traits::KeyedHash;
    use crate::BigInt;

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
