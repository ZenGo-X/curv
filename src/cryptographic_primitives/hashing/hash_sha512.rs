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
use sha2::Sha512;

use crate::BigInt;

pub struct HSha512;

impl Hash for HSha512 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha512::new();

        for value in big_ints {
            hasher.input(&BigInt::to_bytes(value).1);
        }

        let result_hex = hasher.result();
        BigInt::from_bytes(Sign::Positive, &result_hex[..])
    }

    fn create_hash_from_ge<P: ECPoint>(ge_vec: &[&P]) -> P::Scalar {
        let mut hasher = Sha512::new();
        for value in ge_vec {
            hasher.input(&value.pk_to_key_slice());
        }

        let result_hex = hasher.result();
        let result = BigInt::from_bytes(Sign::Positive, &result_hex[..]);
        ECScalar::from(&result)
    }

    fn create_hash_from_slice(byte_slice: &[u8]) -> BigInt {
        let mut hasher = Sha512::new();
        hasher.input(byte_slice);
        let result_hex = hasher.result();
        BigInt::from_bytes(Sign::Positive, &result_hex[..])
    }
}

#[cfg(test)]
mod tests {
    use super::HSha512;
    use super::Hash;
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::traits::{ECPoint, ECScalar};
    use crate::BigInt;

    #[test]
    // Test Vectors taken from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
    fn vector_sha512_test() {
        // Empty message
        let result: BigInt = HSha512::create_hash(&[]);
        assert_eq!(
            result.to_hex(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );

        // 2x256 bit message
        let result: BigInt = HSha512::create_hash(&[
            &BigInt::from_hex("c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f7")
                .unwrap(),
            &BigInt::from_hex("9d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d")
                .unwrap(),
        ]);
        assert_eq!(
            result.to_hex(),
            "46e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d"
        );

        // 512 bit message
        let result: BigInt = HSha512::create_hash(&[&BigInt::from_hex(
            "c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f79d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d",

        )
        .unwrap()]);
        assert_eq!(
            result.to_hex(),
            "46e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d"
        );

        // 1024 bit message
        let result: BigInt = HSha512::create_hash(&[&BigInt::from_hex("fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8").unwrap()]);
        assert_eq!(
            result.to_hex(),
            "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc"
        );
    }

    crate::test_for_all_curves!(create_sha512_from_ge_test);

    fn create_sha512_from_ge_test<P>()
    where
        P: ECPoint,
        P::Scalar: PartialEq + std::fmt::Debug,
    {
        let point = P::base_point2();
        let result1 = HSha512::create_hash_from_ge(&[&point, &P::generator()]);
        assert!(result1.to_big_int().bit_length() > 240);
        let result2 = HSha512::create_hash_from_ge(&[&P::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha512::create_hash_from_ge(&[&P::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
