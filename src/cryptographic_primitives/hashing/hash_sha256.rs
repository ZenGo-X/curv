/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use crate::arithmetic::traits::Converter;
use crate::elliptic::curves::traits::{ECPoint, ECScalar};

use digest::Digest;
use sha2::Sha256;

use crate::BigInt;
pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha256::new();

        for value in big_ints {
            hasher.input(&BigInt::to_vec(value));
        }

        let result_hex = hasher.result();
        BigInt::from(&result_hex[..])
    }

    fn create_hash_from_ge<P: ECPoint>(ge_vec: &[&P]) -> P::Scalar {
        let mut hasher = Sha256::new();
        for value in ge_vec {
            hasher.input(&value.pk_to_key_slice());
        }

        let result_hex = hasher.result();
        let result = BigInt::from(&result_hex[..]);
        ECScalar::from(&result)
    }

    fn create_hash_from_slice(byte_slice: &[u8]) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.input(byte_slice);
        let result_hex = hasher.result();
        BigInt::from(&result_hex[..])
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
    use crate::arithmetic::traits::Converter;
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
    fn create_sha256_from_ge_test_for_all_curves() {
        #[cfg(feature = "ec_secp256k1")]
        create_sha256_from_ge_test::<crate::elliptic::curves::secp256_k1::GE>();
        #[cfg(feature = "ec_ristretto")]
        create_sha256_from_ge_test::<crate::elliptic::curves::curve_ristretto::GE>();
        #[cfg(feature = "ec_ed25519")]
        create_sha256_from_ge_test::<crate::elliptic::curves::ed25519::GE>();
        #[cfg(feature = "ec_jubjub")]
        create_sha256_from_ge_test::<crate::elliptic::curves::curve_jubjub::GE>();
        #[cfg(feature = "ec_bls12_381")]
        create_sha256_from_ge_test::<crate::elliptic::curves::bls12_381::GE>();
        #[cfg(feature = "ec_p256")]
        create_sha256_from_ge_test::<crate::elliptic::curves::p256::GE>();
    }

    fn create_sha256_from_ge_test<P>()
    where P: ECPoint,
          P::Scalar: PartialEq + std::fmt::Debug,
    {
        let point = P::base_point2();
        let result1 = HSha256::create_hash_from_ge(&vec![&point, &P::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha256::create_hash_from_ge(&vec![&P::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&vec![&P::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
