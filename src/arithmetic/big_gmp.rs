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
use std::{ops, ptr};

use gmp::mpz::Mpz;
use gmp::sign::Sign;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::errors::*;
use super::traits::*;

#[derive(PartialOrd, PartialEq, Ord, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BigInt {
    gmp: Mpz,
}

#[allow(deprecated)]
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
    fn to_vec(&self) -> Vec<u8> {
        let bytes: Vec<u8> = self.gmp.borrow().into();
        bytes
    }

    fn to_hex(&self) -> String {
        self.gmp.to_str_radix(16)
    }

    fn from_hex(value: &str) -> Result<BigInt, ParseBigIntFromHexError> {
        Ok(Mpz::from_str_radix(value, 16)
            .map_err(ParseFromHexReason::Gmp)?
            .wrap())
    }
}

impl BasicOps for BigInt {
    fn pow(&self, exponent: u32) -> Self {
        self.gmp.pow(exponent).wrap()
    }

    fn mul(&self, other: &Self) -> Self {
        self * other
    }

    fn sub(&self, other: &Self) -> Self {
        self - other
    }

    fn add(&self, other: &Self) -> Self {
        self + other
    }

    fn abs(&self) -> Self {
        self.gmp.abs().wrap()
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

    fn mod_inv(a: &Self, modulus: &Self) -> Option<Self> {
        Some(a.gmp.invert(&modulus.gmp)?.wrap())
    }

    fn modulus(&self, modulus: &Self) -> Self {
        self.gmp.modulus(&modulus.gmp).wrap()
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
    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        if bit_val {
            self.gmp.setbit(bit);
        } else {
            self.gmp.clrbit(bit);
        }
    }

    fn test_bit(&self, bit: usize) -> bool {
        self.gmp.tstbit(bit)
    }

    fn bit_length(&self) -> usize {
        self.gmp.bit_length()
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

#[allow(deprecated)]
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
    BitXor bitxor,
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

impl_from! { &[u8], u32, i32, u64 }

impl From<&BigInt> for Vec<u8> {
    fn from(bn: &BigInt) -> Vec<u8> {
        (&bn.gmp).into()
    }
}

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
    use super::*;

    use std::cmp;

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        BigInt::sample_below(&BigInt::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = BigInt::from(10);

        for _ in 1..100 {
            let r = BigInt::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        BigInt::sample_range(&BigInt::from(10), &BigInt::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = BigInt::from(10);
        let lower_bound = BigInt::from(5);

        for _ in 1..100 {
            let r = BigInt::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_range_test() {
        let len = 249;

        for _ in 1..100 {
            let a = BigInt::sample(len);
            let b = BigInt::sample(len);
            let lower_bound = cmp::min(a.clone(), b.clone());
            let upper_bound = cmp::max(a.clone(), b.clone());

            let r = BigInt::strict_sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_test() {
        let len = 249;

        for _ in 1..100 {
            let a = BigInt::strict_sample(len);
            assert_eq!(a.bit_length(), len);
        }
    }

    //test mod_sub: a-b mod n where a-b >0
    #[test]
    fn test_mod_sub_modulo() {
        let a = BigInt::from(10);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    //test mod_sub: a-b mod n where a-b <0
    #[test]
    fn test_mod_sub_negative_modulo() {
        let a = BigInt::from(5);
        let b = BigInt::from(10);
        let modulo = BigInt::from(3);
        let res = BigInt::from(1);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_mul() {
        let a = BigInt::from(4);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_mul(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_pow() {
        let a = BigInt::from(2);
        let b = BigInt::from(3);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_pow(&a, &b, &modulo));
    }

    #[test]
    fn test_to_hex() {
        let b = BigInt::from(11);
        assert_eq!("b", b.to_hex());
    }

    #[test]
    fn test_from_hex() {
        let a = BigInt::from(11);
        assert_eq!(BigInt::from_hex(&a.to_hex()).unwrap(), a);
    }
}

/// Tests that ring_algorithm work as expected
#[cfg(test)]
mod ring_algorithm_test {
    const PRIME: u32 = u32::MAX - 4;

    use super::*;

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
        let n_inv_expected = BigInt::mod_inv(&n, &prime).unwrap();
        let n_inv_actual = ring_algorithm::modulo_inverse(n, prime.clone()).unwrap();
        assert_eq!(n_inv_expected, n_inv_actual.modulus(&prime));
    }

    fn test_xgcd(a: BigInt, b: BigInt) {
        let (s1, p1, q1) = BigInt::egcd(&a, &b);
        let (s2, p2, q2) = ring_algorithm::normalized_extended_euclidian_algorithm(a, b);
        assert_eq!((s1, p1, q1), (s2, p2, q2));
    }
}
