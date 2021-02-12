/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use crate::arithmetic::traits::*;
use crate::elliptic::curves::traits::{ECPoint, ECScalar};

use digest::Digest;
use sha2::Sha256;

use crate::BigInt;
pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha256::new();

        for value in big_ints {
            hasher.input(&BigInt::to_bytes(value));
        }

        let result_hex = hasher.result();
        BigInt::from_bytes(&result_hex[..])
    }

    fn create_hash_from_ge<P: ECPoint>(ge_vec: &[&P]) -> P::Scalar {
        let mut hasher = Sha256::new();
        for value in ge_vec {
            hasher.input(&value.pk_to_key_slice());
        }

        let result_hex = hasher.result();
        let result = BigInt::from_bytes(&result_hex[..]);
        ECScalar::from(&result)
    }

    fn create_hash_from_slice(byte_slice: &[u8]) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.input(byte_slice);
        let result_hex = hasher.result();
        BigInt::from_bytes(&result_hex[..])
    }
}

#[cfg(test)]
mod tests {
    use super::HSha256;
    use super::Hash;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;
    extern crate hex;
    extern crate sha2;
    use crate::arithmetic::traits::*;
    use sha2::Digest;
    use sha2::Sha256;

    #[test]
    fn test_byte_vec() {
        let message: Vec<u8> = vec![0, 1];
        let big_int0 = BigInt::from(message[0] as i32);
        let big_int1 = BigInt::from(message[1] as i32);

        let result = HSha256::create_hash(&[&big_int0, &big_int1]).to_hex();
        let mut hasher = Sha256::new();
        hasher.input(&message);
        let result2 = hex::encode(hasher.result());
        assert_eq!(result, result2);
    }

    #[test]
    // Test Vectors taken from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
    fn vector_sha256_test() {
        // Empty Message
        let result: BigInt = HSha256::create_hash(&[]);
        assert_eq!(
            result.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // 256 bit message
        let result: BigInt = HSha256::create_hash(&[&BigInt::from_hex(
            "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95",
        )
        .unwrap()]);
        assert_eq!(
            result.to_hex(),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 2x128 bit messages
        let result: BigInt = HSha256::create_hash(&[
            &BigInt::from_hex("09fc1accc230a205e4a208e64a8f2042").unwrap(),
            &BigInt::from_hex("91f581a12756392da4b8c0cf5ef02b95").unwrap(),
        ]);
        assert_eq!(
            result.to_hex(),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 512 bit message
        let result: BigInt = HSha256::create_hash(&[&BigInt::from_hex("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509").unwrap()]);
        assert_eq!(
            result.to_hex(),
            "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa"
        );
    }

    crate::test_for_all_curves!(create_sha256_from_ge_test);

    fn create_sha256_from_ge_test<P>()
    where
        P: ECPoint,
        P::Scalar: PartialEq + std::fmt::Debug,
    {
        let point = P::base_point2();
        let result1 = HSha256::create_hash_from_ge(&[&point, &P::generator()]);
        assert!(result1.to_big_int().bit_length() > 240);
        let result2 = HSha256::create_hash_from_ge(&[&P::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&[&P::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
