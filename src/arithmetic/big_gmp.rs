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

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::sync::atomic;
use std::{error, fmt, ops, ptr};

use gmp::mpz::Mpz;
use gmp::sign::Sign;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use super::traits::{
    BitManipulation, ConvertFrom, Converter, Modulo, NumberTests, Samplable, ZeroizeBN, EGCD,
};

#[derive(PartialOrd, PartialEq, Ord, Eq, Clone, Debug)]
pub struct BigInt {
    gmp: Mpz,
}

impl ZeroizeBN for BigInt {
    fn zeroize_bn(&mut self) {
        unsafe { ptr::write_volatile(&mut self.gmp, Mpz::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Zeroize for BigInt {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(&mut self.gmp, Mpz::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Converter for BigInt {
    fn to_vec(value: &BigInt) -> Vec<u8> {
        let bytes: Vec<u8> = value.gmp.borrow().into();
        bytes
    }

    fn to_hex(&self) -> String {
        self.gmp.to_str_radix(super::HEX_RADIX)
    }

    fn from_hex(value: &str) -> BigInt {
        Mpz::from_str_radix(value, super::HEX_RADIX)
            .expect("Error in serialization")
            .wrap()
    }
}

// TODO: write unit test
impl Modulo for BigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.gmp.powm(&exponent.gmp, &modulus.gmp).wrap()
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.gmp.mod_floor(&modulus.gmp) * b.gmp.mod_floor(&modulus.gmp))
            .mod_floor(&modulus.gmp)
            .wrap()
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.gmp.mod_floor(&modulus.gmp);
        let b_m = b.gmp.mod_floor(&modulus.gmp);

        let sub_op = a_m - b_m + &modulus.gmp;
        sub_op.mod_floor(&modulus.gmp).wrap()
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.gmp.mod_floor(&modulus.gmp) + b.gmp.mod_floor(&modulus.gmp))
            .mod_floor(&modulus.gmp)
            .wrap()
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        a.gmp.invert(&modulus.gmp).unwrap().wrap()
    }

    fn modulus(a: &Self, modulus: &Self) -> Self {
        a.gmp.modulus(&modulus.gmp).wrap()
    }
}

impl Samplable for BigInt {
    fn sample_below(upper: &Self) -> Self {
        assert!(*upper > Self::zero());

        let bits = upper.gmp.bit_length();
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        lower + Self::sample_below(&(upper - lower))
    }

    fn strict_sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        loop {
            let n = lower + Self::sample_below(&(upper - lower));
            if n > *lower && n < *upper {
                return n;
            }
        }
    }

    fn sample(bit_size: usize) -> Self {
        let mut rng = OsRng::new().unwrap();
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        rng.fill_bytes(&mut buf);
        Self::from(&*buf) >> (bytes * 8 - bit_size)
    }

    fn strict_sample(bit_size: usize) -> Self {
        loop {
            let n = Self::sample(bit_size);
            if n.gmp.bit_length() == bit_size {
                return n;
            }
        }
    }
}

impl NumberTests for BigInt {
    fn is_zero(me: &Self) -> bool {
        me.gmp.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.gmp.is_multiple_of(&Mpz::from(2))
    }
    fn is_negative(me: &Self) -> bool {
        matches!(me.gmp.sign(), Sign::Negative)
    }
}

impl EGCD for BigInt {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        let (s, p, q) = a.gmp.gcdext(&b.gmp);
        (s.wrap(), p.wrap(), q.wrap())
    }
}

impl BitManipulation for BigInt {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        if bit_val {
            self.gmp.setbit(bit);
        } else {
            self.gmp.clrbit(bit);
        }
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        self.gmp.tstbit(bit)
    }
}

macro_rules! impl_try_from {
    ($($primitive:ty),*$(,)?) => {
        $(
        impl TryFrom<&BigInt> for $primitive {
            type Error = TryFromBigIntError;

            fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
                Option::<$primitive>::from(&value.gmp)
                    .ok_or(TryFromBigIntError { type_name: stringify!($primitive) })
            }
        }
        )*
    };
}

impl_try_from! { u64, i64 }

#[derive(Debug)]
pub struct TryFromBigIntError {
    type_name: &'static str,
}

impl fmt::Display for TryFromBigIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conversion from BigInt to {} overflowed", self.type_name)
    }
}

impl error::Error for TryFromBigIntError {}

impl ConvertFrom<BigInt> for u64 {
    fn _from(x: &BigInt) -> u64 {
        let opt_x: Option<u64> = (&x.gmp).into();
        opt_x.unwrap()
    }
}

macro_rules! impl_ops {
    () => {};
    ($op: ident $func:ident, $($rest:tt)*) => {
        impl ops::$op for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                (&self.gmp).$func(&rhs.gmp).wrap()
            }
        }
        impl ops::$op for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                self.gmp.$func(rhs.gmp).wrap()
            }
        }
        impl ops::$op<BigInt> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: BigInt) -> Self::Output {
                (&self.gmp).$func(rhs.gmp).wrap()
            }
        }
        impl ops::$op<&BigInt> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: &BigInt) -> Self::Output {
                self.gmp.$func(&rhs.gmp).wrap()
            }
        }
        impl_ops!{ $($rest)* }
    };
    ($op: ident $func:ident $primitive:ty, $($rest:tt)*) => {
        impl ops::$op<$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                self.gmp.$func(rhs).wrap()
            }
        }
        impl ops::$op<$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                (&self.gmp).$func(rhs).wrap()
            }
        }
        impl_ops!{ $($rest)* }
    };
}

impl_ops! {
    Add add,
    Sub sub,
    Mul mul,
    Div div,
    Rem rem,
    Shl shl usize,
    Shr shr usize,
}

impl ops::Neg for BigInt {
    type Output = BigInt;
    fn neg(self) -> Self::Output {
        self.gmp.neg().wrap()
    }
}
impl ops::Neg for &BigInt {
    type Output = BigInt;
    fn neg(self) -> Self::Output {
        (&self.gmp).neg().wrap()
    }
}

impl Zero for BigInt {
    fn zero() -> Self {
        Mpz::zero().wrap()
    }

    fn is_zero(&self) -> bool {
        self.gmp.is_zero()
    }
}

impl One for BigInt {
    fn one() -> Self {
        Mpz::one().wrap()
    }
    fn is_one(&self) -> bool {
        self.gmp.is_one()
    }
}

impl ring_algorithm::RingNormalize for BigInt {
    fn leading_unit(&self) -> Self {
        match self.gmp.sign() {
            Sign::Negative => -BigInt::one(),
            _ => BigInt::one(),
        }
    }

    fn normalize_mut(&mut self) {
        self.gmp = self.gmp.abs();
    }
}

macro_rules! impl_from {
    ($($type:ty),*$(,)?) => {
    $(
    impl From<$type> for BigInt {
        fn from(x: $type) -> Self {
            Self{ gmp: Mpz::from(x) }
        }
    }
    )*
    };
}

impl_from! { &[u8], u32, u64 }

/// Internal helper trait. Creates short-hand for wrapping Mpz into BigInt.
trait Wrap {
    fn wrap(self) -> BigInt;
}
impl Wrap for Mpz {
    fn wrap(self) -> BigInt {
        BigInt { gmp: self }
    }
}

#[cfg(test)]
mod tests {
    use super::Converter;
    use super::Modulo;
    use super::Mpz;
    use super::Samplable;

    use std::cmp;

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        Mpz::sample_below(&Mpz::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = Mpz::from(10);

        for _ in 1..100 {
            let r = Mpz::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        Mpz::sample_range(&Mpz::from(10), &Mpz::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = Mpz::from(10);
        let lower_bound = Mpz::from(5);

        for _ in 1..100 {
            let r = Mpz::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_range_test() {
        let len = 249;

        for _ in 1..100 {
            let a = Mpz::sample(len);
            let b = Mpz::sample(len);
            let lower_bound = cmp::min(a.clone(), b.clone());
            let upper_bound = cmp::max(a.clone(), b.clone());

            let r = Mpz::strict_sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_test() {
        let len = 249;

        for _ in 1..100 {
            let a = Mpz::strict_sample(len);
            assert_eq!(a.bit_length(), len);
        }
    }

    //test mod_sub: a-b mod n where a-b >0
    #[test]
    fn test_mod_sub_modulo() {
        let a = Mpz::from(10);
        let b = Mpz::from(5);
        let modulo = Mpz::from(3);
        let res = Mpz::from(2);
        assert_eq!(res, Mpz::mod_sub(&a, &b, &modulo));
    }

    //test mod_sub: a-b mod n where a-b <0
    #[test]
    fn test_mod_sub_negative_modulo() {
        let a = Mpz::from(5);
        let b = Mpz::from(10);
        let modulo = Mpz::from(3);
        let res = Mpz::from(1);
        assert_eq!(res, Mpz::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_mul() {
        let a = Mpz::from(4);
        let b = Mpz::from(5);
        let modulo = Mpz::from(3);
        let res = Mpz::from(2);
        assert_eq!(res, Mpz::mod_mul(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_pow() {
        let a = Mpz::from(2);
        let b = Mpz::from(3);
        let modulo = Mpz::from(3);
        let res = Mpz::from(2);
        assert_eq!(res, Mpz::mod_pow(&a, &b, &modulo));
    }

    #[test]
    fn test_to_hex() {
        let b = Mpz::from(11);
        assert_eq!("b", b.to_hex());
    }

    #[test]
    fn test_from_hex() {
        let a = Mpz::from(11);
        assert_eq!(Mpz::from_hex(&a.to_hex()), a);
    }
}

/// Tests that ring_algorithm work as expected
#[cfg(test)]
mod ring_algorithm_test {
    const PRIME: u32 = u32::MAX - 4;

    use super::*;
    use crate::arithmetic::traits::{Modulo, EGCD};

    proptest::proptest! {
        #[test]
        fn fuzz_inverse(n in 1..PRIME) {
            test_inverse(BigInt::from(n))
        }
        #[test]
        fn fuzz_xgcd(a in 1u32.., b in 1u32..) {
            test_xgcd(BigInt::from(a), BigInt::from(b))
        }
    }

    fn test_inverse(n: BigInt) {
        let prime = BigInt::from(PRIME);
        let n_inv_expected = n.mod_inv(&prime).unwrap();
        let n_inv_actual =
            ring_algorithm::modulo_inverse(Arithmetic(n), Arithmetic(prime.clone())).unwrap();
        assert_eq!(n_inv_expected, n_inv_actual.into_inner().modulus(&prime));
    }

    fn test_xgcd(a: BigInt, b: BigInt) {
        let (s1, p1, q1) = BigInt::egcd(&a, &b);
        let (s2, p2, q2) =
            ring_algorithm::normalized_extended_euclidian_algorithm(Arithmetic(a), Arithmetic(b));
        assert_eq!(s1, s2.into_inner());
        assert_eq!(p1, p2.into_inner());
        assert_eq!(q1, q2.into_inner());
    }
}
