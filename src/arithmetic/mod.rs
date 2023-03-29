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
mod macros;
mod samplable;
mod serde_support;
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

pub use errors::{ParseBigIntError, TryFromBigIntError};
pub use traits::*;

#[cfg(test)]
mod test {
    use std::{fmt, ops::*};

    use proptest_derive::Arbitrary;

    use super::*;

    #[test]
    fn serializes_deserializes() {
        use serde_test::{assert_tokens, Configure, Token::*};
        for bigint in [BigInt::zero(), BigInt::sample(1024)] {
            let bytes = bigint.to_bytes();
            let tokens = [Bytes(bytes.leak())];
            assert_tokens(&bigint.compact(), &tokens)
        }
    }

    #[test]
    fn deserializes_bigint_represented_as_seq() {
        use serde_test::{assert_de_tokens, Configure, Token::*};

        let number = BigInt::sample(1024);
        let bytes = number.to_bytes();

        let mut tokens = vec![Seq {
            len: Option::Some(bytes.len()),
        }];
        tokens.extend(bytes.into_iter().map(U8));
        tokens.push(SeqEnd);

        assert_de_tokens(&number.compact(), &tokens);
    }

    #[test]
    fn serializes_deserializes_in_human_readable_format() {
        use serde_test::{assert_tokens, Configure, Token::*};

        let number = BigInt::sample(1024);
        let tokens = [Str(Box::leak(
            hex::encode(number.to_bytes()).into_boxed_str(),
        ))];

        assert_tokens(&number.readable(), &tokens);
    }

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
    fn serializing_to_vec() {
        let n = BigInt::from(1_000_000_u32);
        let v = n.to_bytes();
        assert_eq!(v, b"\x0f\x42\x40");
    }

    #[test]
    fn deserializing_from_bytes() {
        let v: &[u8] = b"\x0f\x42\x40";
        let n = BigInt::from_bytes(v);
        assert_eq!(n, BigInt::from(1_000_000_u32))
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
        fn fuzz_mod_ops(ops: Vec<(ModOp, u32)>) {
            test_mod_ops(ops)
        }
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

    proptest::proptest! {
        #[test]
        fn fuzz_modulo_invert(a in 0..(u32::MAX - 4)) {
            modulo_invert(a, u32::MAX - 4)
        }
    }

    fn modulo_invert(a: u32, m: u32) {
        let (a, m) = (BigInt::from(a), BigInt::from(m));
        let inv = BigInt::mod_inv(&a, &m).unwrap();
        assert!(BigInt::zero() <= inv && inv < m);
        let one = BigInt::mod_mul(&a, &inv, &m);
        assert_eq!(one, BigInt::one());
    }

    #[test]
    #[should_panic]
    fn mod_pow_panics_if_exp_is_negative() {
        BigInt::mod_pow(&BigInt::from(3), &(-BigInt::one()), &BigInt::from(7));
    }

    const PRIMES: &[&str] = &[
        "2",
        "3",
        "5",
        "7",
        "11",

        "13756265695458089029",
        "13496181268022124907",
        "10953742525620032441",
        "17908251027575790097",

        // https://golang.org/issue/638
        "18699199384836356663",

        "98920366548084643601728869055592650835572950932266967461790948584315647051443",
        "94560208308847015747498523884063394671606671904944666360068158221458669711639",

        // http://primes.utm.edu/lists/small/small3.html
        "449417999055441493994709297093108513015373787049558499205492347871729927573118262811508386655998299074566974373711472560655026288668094291699357843464363003144674940345912431129144354948751003607115263071543163",
        "230975859993204150666423538988557839555560243929065415434980904258310530753006723857139742334640122533598517597674807096648905501653461687601339782814316124971547968912893214002992086353183070342498989426570593",
        "5521712099665906221540423207019333379125265462121169655563495403888449493493629943498064604536961775110765377745550377067893607246020694972959780839151452457728855382113555867743022746090187341871655890805971735385789993",
        "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123",
        // ECC primes: http://tools.ietf.org/html/draft-ladd-safecurves-02
        "3618502788666131106986593281521497120414687020801267626233049500247285301239",                                                                                  // Curve1174: 2^251-9
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",                                                                                 // Curve25519: 2^255-19
        "9850501549098619803069760025035903451269934817616361666987073351061430442874302652853566563721228910201656997576599",                                           // E-382: 2^382-105
        "42307582002575910332922579714097346549017899709713998034217522897561970639123926132812109468141778230245837569601494931472367",                                 // Curve41417: 2^414-17
        "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", // E-521: 2^521-1
    ];

    #[test]
    fn probabilistically_test_primes() {
        for prime in PRIMES {
            for &n in &[0, 5, 20] {
                let prime = BigInt::from_str_radix(prime, 10).unwrap();
                assert!(prime.is_probable_prime(n))
            }
        }
    }

    #[test]
    fn display_bigint_returns_decimal_representation() {
        let s = BigInt::from(12345).to_string();
        assert_eq!(s, "12345")
    }

    proptest::proptest! {
        #[test]
        fn fuzz_searching_next_prime(n in 1u64..) {
            test_find_next_prime(n)
        }
    }

    fn test_find_next_prime(n: u64) {
        let n = BigInt::from(n);
        let prime = n.next_prime();
        assert!(n < prime);
        assert!(prime.is_probable_prime(20));
    }

    /// This test will fail to compile if BigInt doesn't implement certain traits.
    #[test]
    fn big_int_implements_all_required_trait() {
        assert_big_int_implements_all_required_traits::<BigInt>();
    }

    /// A no-op function that takes BigInt implementation as a generic param. It's only purpose
    /// is to abort compilation if BigInt doesn't implement certain traits.
    #[allow(deprecated)]
    fn assert_big_int_implements_all_required_traits<T>()
    where
        T: fmt::Display + fmt::Debug,
        // Basic traits from self::traits module
        T: Converter + BasicOps + Modulo + Samplable + NumberTests + EGCD + BitManipulation,
        T: Primes,
        // Deprecated but not deleted yet traits from self::traits module
        T: ZeroizeBN,
        u64: ConvertFrom<BigInt>,
        // Foreign traits implementations
        T: zeroize::Zeroize + num_traits::One + num_traits::Zero,
        T: num_traits::Num + num_integer::Integer + num_integer::Roots,
        // Conversion traits
        for<'a> u64: std::convert::TryFrom<&'a BigInt>,
        for<'a> i64: std::convert::TryFrom<&'a BigInt>,
        BigInt: From<u16> + From<u32> + From<i32> + From<u64>,
        // STD Operators
        BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitAnd<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitAnd<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        for<'a> &'a BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitAnd<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> &'a BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitAnd<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
        for<'a> &'a BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
        BigInt: Add<u64, Output = BigInt>
            + Sub<u64, Output = BigInt>
            + Mul<u64, Output = BigInt>
            + Div<u64, Output = BigInt>
            + Rem<u64, Output = BigInt>,
        for<'a> &'a BigInt: Add<u64, Output = BigInt>
            + Sub<u64, Output = BigInt>
            + Mul<u64, Output = BigInt>
            + Div<u64, Output = BigInt>
            + Rem<u64, Output = BigInt>,
        u64: Add<BigInt, Output = BigInt>
            + Sub<BigInt, Output = BigInt>
            + Mul<BigInt, Output = BigInt>,
        for<'a> u64: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>,
        // Assigns traits
        for<'a> BigInt: AddAssign
            + AddAssign<&'a BigInt>
            + AddAssign<u64>
            + BitAndAssign
            + BitAndAssign<&'a BigInt>
            + BitOrAssign
            + BitOrAssign<&'a BigInt>
            + BitXorAssign
            + BitXorAssign<&'a BigInt>
            + DivAssign
            + DivAssign<&'a BigInt>
            + DivAssign<u64>
            + MulAssign
            + MulAssign<&'a BigInt>
            + MulAssign<u64>
            + RemAssign
            + RemAssign<&'a BigInt>
            + RemAssign<u64>
            + SubAssign
            + SubAssign<&'a BigInt>
            + SubAssign<u64>,
    {
    }
}
