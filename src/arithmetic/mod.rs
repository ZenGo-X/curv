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

mod errors;
mod samplable;
pub mod traits;

#[cfg(not(any(feature = "rust-gmp-kzen", feature = "num-bigint")))]
compile_error!("You need to choose which bigint implementation to use. See crate features.");
#[cfg(all(feature = "rust-gmp-kzen", feature = "num-bigint"))]
compile_error!("You can choose only one bigint implementation. See crate features.");

#[cfg(feature = "rust-gmp-kzen")]
mod big_gmp;
#[cfg(feature = "rust-gmp-kzen")]
pub use big_gmp::BigInt;

#[cfg(feature = "num-bigint")]
mod big_native;
#[cfg(feature = "num-bigint")]
pub use big_native::BigInt;

pub use errors::{ParseBigIntFromHexError, TryFromBigIntError};
pub use traits::*;

#[cfg(test)]
mod test {
    use std::ops::*;

    use proptest_derive::Arbitrary;

    use super::*;

    #[test]
    fn serializing_to_hex() {
        let n = BigInt::from(1_000_000_u32);
        let h = n.to_hex();
        assert_eq!(h, "f4240")
    }

    #[test]
    fn deserializing_from_hex() {
        let h = "f4240";
        let n = BigInt::from_hex(h).unwrap();
        assert_eq!(n, BigInt::from(1_000_000_u32));
    }

    #[test]
    fn serializing_negative_to_hex() {
        let n = BigInt::from(-1_000_000_i32);
        let h = n.to_hex();
        assert_eq!(h, "-f4240")
    }

    #[test]
    fn deserializing_negative_from_hex() {
        let h = "-f4240";
        let n = BigInt::from_hex(h).unwrap();
        assert_eq!(n, BigInt::from(-1_000_000_i32));
    }

    #[test]
    fn serializing_to_vec() {
        let n = BigInt::from(1_000_000_u32);
        let v = n.to_vec();
        assert_eq!(v, b"\x0f\x42\x40");
    }

    #[test]
    fn deserializing_from_bytes() {
        let v: &[u8] = b"\x0f\x42\x40";
        let n = BigInt::from(v);
        assert_eq!(n, BigInt::from(1_000_000_u32))
    }

    #[test]
    fn serializing_negative_to_vec_discards_sign() {
        assert_eq!(
            BigInt::from(-1_000_000_i32).to_vec(),
            BigInt::from(1_000_000_i32).to_vec()
        );
    }

    /// This test will fail to compile if BigInt doesn't implement certain traits.
    #[test]
    fn big_int_implements_all_required_trait() {
        assert_big_int_implements_all_required_traits::<BigInt>();
    }

    #[test]
    fn count_bits() {
        let mut n = BigInt::one();
        let mut expected_bits = 1_usize;
        for _ in 0..100 {
            assert_eq!(n.bit_length(), expected_bits);
            n <<= 1;
            expected_bits += 1;
        }
    }

    #[test]
    fn test_bits() {
        let n = BigInt::from(0b1011001);
        let expectations = vec![true, false, true, true, false, false, true];

        for (i, expect) in expectations.into_iter().enumerate() {
            let i = 7 - i - 1;
            assert_eq!(n.test_bit(i), expect, "testing {} bit", i)
        }
    }

    #[test]
    fn test_setting_bit() {
        let mut n = BigInt::zero();

        n.set_bit(4, true);
        assert_eq!(n, BigInt::from(0b10000));
        n.set_bit(1, true);
        assert_eq!(n, BigInt::from(0b10010));
        n.set_bit(4, true);
        assert_eq!(n, BigInt::from(0b10010));
        n.set_bit(4, false);
        assert_eq!(n, BigInt::from(0b10));
        n.set_bit(2, false);
        assert_eq!(n, BigInt::from(0b10));
        n.set_bit(1, false);
        assert_eq!(n, BigInt::from(0));
    }

    #[test]
    #[should_panic]
    fn sample_below_zero_should_panic() {
        BigInt::sample_below(&BigInt::from(-1));
    }

    #[test]
    #[should_panic]
    fn sample_within_invalid_range_should_panic() {
        BigInt::sample_range(&BigInt::from(9), &BigInt::from(3));
    }

    #[test]
    #[should_panic]
    fn strict_sample_within_invalid_range_should_panic() {
        BigInt::sample_range(&BigInt::from(5), &BigInt::from(5));
    }

    #[test]
    fn sample_on_zero_bits_returns_zero() {
        assert_eq!(BigInt::sample(0), BigInt::zero());
        assert_eq!(BigInt::strict_sample(0), BigInt::zero());
    }

    #[test]
    fn fuzz_sample_returns_number_not_more_than_n_bits_length() {
        const BITS: usize = 100;

        for _ in 0..100 {
            let n = BigInt::sample(BITS);
            assert!(
                n.bit_length() <= BITS,
                "returned {} bits length number",
                n.bit_length()
            );
        }
    }

    #[test]
    fn fuzz_strict_sample_returns_number_exactly_n_bits_length() {
        const BITS: usize = 100;

        for _ in 0..100 {
            let n = BigInt::strict_sample(BITS);
            assert_eq!(
                n.bit_length(),
                BITS,
                "returned {} bits length number",
                n.bit_length()
            );
        }
    }

    #[test]
    fn fuzz_sample_range() {
        let a = BigInt::from(500);
        let b = &a * &a;

        for _ in 0..100 {
            let n = BigInt::sample_range(&a, &b);
            assert!(
                a <= n && n < b,
                "assertion failed: {:?} <= {:?} < {:?}",
                a,
                n,
                b
            );
        }
    }

    #[test]
    fn fuzz_strict_sample_range() {
        let a = BigInt::from(500);
        let b = &a * &a;

        for _ in 0..100 {
            let n = BigInt::strict_sample_range(&a, &b);
            assert!(
                a <= n && n < b,
                "assertion failed: {:?} < {:?} < {:?}",
                a,
                n,
                b
            );
        }
    }

    #[test]
    fn sample_below() {
        let a = BigInt::from(500);

        for _ in 0..100 {
            let n = BigInt::sample_below(&a);
            assert!(n < a, "assertion failed: {:?} < {:?}", n, a);
        }
    }

    #[derive(Arbitrary, Debug, Copy, Clone)]
    enum ModOp {
        Add,
        Sub,
        Mul,
    }

    proptest::proptest! {
        #[test]
        fn fuzz_mod_ops_big(ops: Vec<(ModOp, u32)>) {
            test_mod_ops(ops)
        }
    }

    #[test]
    fn test_mod_ops_corner_cases() {
        let actual = BigInt::mod_sub(&BigInt::zero(), &BigInt::one(), &BigInt::from(4));
        let expected = BigInt::from(3);
        assert_eq!(actual, expected);
    }

    fn test_mod_ops(ops: Vec<(ModOp, u32)>) {
        let mut actual = BigInt::zero();
        let mut expected = 0u32;
        let module = BigInt::from(u32::MAX) + BigInt::one();

        for (op, n) in ops {
            let was = expected;
            match op {
                ModOp::Add => {
                    actual = BigInt::mod_add(&actual, &BigInt::from(n), &module);
                    expected = expected.wrapping_add(n);
                }
                ModOp::Sub => {
                    actual = BigInt::mod_sub(&actual, &BigInt::from(n), &module);
                    expected = expected.wrapping_sub(n);
                }
                ModOp::Mul => {
                    actual = BigInt::mod_mul(&actual, &BigInt::from(n), &module);
                    expected = expected.wrapping_mul(n);
                }
            }
            assert_eq!(actual, BigInt::from(expected), "{} [{:?}] {}", was, op, n)
        }
    }

    /// A no-op function that takes BigInt implementation as a generic param. It's only purpose
    /// is to abort compilation if BigInt doesn't implement certain traits.
    #[allow(deprecated)]
    fn assert_big_int_implements_all_required_traits<T>()
    where
        // Basic traits from self::traits module
        T: Converter + BasicOps + Modulo + Samplable + BitManipulation, // + NumberTests + EGCD + BitManipulation,
        // Deprecated but not deleted yet traits from self::traits module
        T: ZeroizeBN,
        // u64: ConvertFrom<BigInt>,
        // Foreign traits implementations
        T: zeroize::Zeroize + ring_algorithm::RingNormalize + num_traits::One + num_traits::Zero,
        for<'a> &'a T: ring_algorithm::EuclideanRingOperation<T>,
        // Conversion traits
        // for<'a> u64: std::convert::TryFrom<&'a BigInt>,
        // for<'a> i64: std::convert::TryFrom<&'a BigInt>,
        // for<'a> BigInt: From<&'a [u8]> + From<u32> + From<i32> + From<u64>,
        // STD Operators
        BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        for<'a> &'a BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> &'a BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
        for<'a> &'a BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
        // Assigns traits
        for<'a> BigInt: AddAssign
            + AddAssign<&'a BigInt>
            + BitAndAssign
            + BitAndAssign<&'a BigInt>
            + BitOrAssign
            + BitOrAssign<&'a BigInt>
            + BitXorAssign
            + BitXorAssign<&'a BigInt>
            + DivAssign
            + DivAssign<&'a BigInt>
            + MulAssign
            + MulAssign<&'a BigInt>
            + RemAssign
            + RemAssign<&'a BigInt>
            + SubAssign
            + SubAssign<&'a BigInt>,
    {
    }
}
