/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use crate::arithmetic::traits::Converter;
use crate::elliptic::curves::traits::{ECPoint, ECScalar};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hex::decode;

use crate::BigInt;
use crate::{FE, GE};

pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha256::new();

        for value in big_ints {
            hasher.input(&BigInt::to_vec(value));
        }

        let result_string = hasher.result_str();

        let result_bytes = decode(result_string).unwrap();

        BigInt::from(&result_bytes[..])
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut hasher = Sha256::new();
        for value in ge_vec {
            hasher.input(&value.pk_to_key_slice());
        }

        let result_string = hasher.result_str();
        let result_bytes = decode(result_string).unwrap();
        let result = BigInt::from(&result_bytes[..]);
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::HSha256;
    use super::Hash;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;
    use crate::GE;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_sha256_test() {
        HSha256::create_hash(&vec![]);

        let result = HSha256::create_hash(&vec![&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }

    #[test]
    fn create_sha256_from_ge_test() {
        let point = GE::base_point2();
        let result1 = HSha256::create_hash_from_ge(&vec![&point, &GE::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
