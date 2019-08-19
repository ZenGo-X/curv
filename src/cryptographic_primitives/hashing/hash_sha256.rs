/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use arithmetic::traits::Converter;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use elliptic::curves::traits::{ECPoint, ECScalar};
use hex::decode;

use BigInt;
use {FE, GE};

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
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use BigInt;
    use GE;

    #[test]
    // Test Vectors taken from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
    fn vector_sha256_test() {
        // Empty Message
        let result: BigInt = HSha256::create_hash(&vec![]);
        assert_eq!(
            result.to_str_radix(16),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // 256 bit message
        let result: BigInt = HSha256::create_hash(&vec![&BigInt::from_str_radix(
            "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95",
            16,
        )
        .unwrap()]);
        assert_eq!(
            result.to_str_radix(16),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 2x128 bit messages
        let result: BigInt = HSha256::create_hash(&vec![
            &BigInt::from_str_radix("09fc1accc230a205e4a208e64a8f2042", 16).unwrap(),
            &BigInt::from_str_radix("91f581a12756392da4b8c0cf5ef02b95", 16).unwrap(),
        ]);
        assert_eq!(
            result.to_str_radix(16),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 512 bit message
        let result: BigInt = HSha256::create_hash(&vec![&BigInt::from_str_radix("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509", 16).unwrap()]);
        assert_eq!(
            result.to_str_radix(16),
            "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa"
        );
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
