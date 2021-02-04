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

use super::traits::{
    BitManipulation, ConvertFrom, Converter, Modulo, NumberTests, Samplable, ZeroizeBN, EGCD,
};
use gmp::mpz::Mpz;
use rand::rngs::OsRng;
use rand::RngCore;

use std::borrow::Borrow;
use std::sync::atomic;
use std::{ops, ptr};

pub type BigInt = Mpz;

impl ZeroizeBN for Mpz {
    fn zeroize_bn(&mut self) {
        unsafe { ptr::write_volatile(self, BigInt::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Converter for Mpz {
    fn to_vec(value: &Mpz) -> Vec<u8> {
        let bytes: Vec<u8> = value.borrow().into();
        bytes
    }

    fn to_hex(&self) -> String {
        self.to_str_radix(super::HEX_RADIX)
    }

    fn from_hex(value: &str) -> Mpz {
        BigInt::from_str_radix(value, super::HEX_RADIX).expect("Error in serialization")
    }
}

// TODO: write unit test
impl Modulo for Mpz {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.powm(exponent, modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);

        let sub_op = a_m - b_m + modulus;
        sub_op.mod_floor(modulus)
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) + b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        a.invert(modulus).unwrap()
    }
}

impl Samplable for Mpz {
    fn sample_below(upper: &Self) -> Self {
        assert!(*upper > Mpz::zero());

        let bits = upper.bit_length();
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
            if n.bit_length() == bit_size {
                return n;
            }
        }
    }
}

impl NumberTests for Mpz {
    fn is_zero(me: &Self) -> bool {
        me.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.is_multiple_of(&Mpz::from(2))
    }
    fn is_negative(me: &Self) -> bool {
        *me < Mpz::from(0)
    }
}

impl EGCD for Mpz {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        a.gcdext(b)
    }
}

impl BitManipulation for Mpz {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        if bit_val {
            self.setbit(bit);
        } else {
            self.clrbit(bit);
        }
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        self.tstbit(bit)
    }
}

impl ConvertFrom<Mpz> for u64 {
    fn _from(x: &Mpz) -> u64 {
        let opt_x: Option<u64> = x.into();
        opt_x.unwrap()
    }
}

/// Wraps BigInt making it compatible with [ring_algorithm] crate
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Arithmetic<T>(T);

impl Arithmetic<BigInt> {
    pub fn wrap(n: BigInt) -> Self {
        Self(n)
    }
}

impl<T> Arithmetic<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> ops::Deref for Arithmetic<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> ops::DerefMut for Arithmetic<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

macro_rules! impl_ops {
    ($($op: ident $func:ident ($($t:tt)+)),+$(,)?) => {
        $(
        impl ops::$op for &Arithmetic<BigInt> {
            type Output = Arithmetic<BigInt>;
            fn $func(self, rhs: Self) -> Self::Output {
                Arithmetic(&self.0 $($t)+ &rhs.0)
            }
        }
        impl ops::$op for Arithmetic<BigInt> {
            type Output = Self;
            fn $func(self, rhs: Self) -> Self::Output {
                Arithmetic(self.0 $($t)+ rhs.0)
            }
        }
        )+
    };
}

impl_ops! {
    Add add (+),
    Sub sub (-),
    Mul mul (*),
    Div div (/),
    Rem rem (%),
}

impl num_traits::Zero for Arithmetic<BigInt> {
    fn zero() -> Self {
        Arithmetic(BigInt::zero())
    }

    fn is_zero(&self) -> bool {
        self.0 == BigInt::zero()
    }
}

impl num_traits::One for Arithmetic<BigInt> {
    fn one() -> Self {
        Arithmetic(BigInt::one())
    }
}

impl ring_algorithm::RingNormalize for Arithmetic<BigInt> {
    fn leading_unit(&self) -> Self {
        if self.0 >= BigInt::zero() {
            Arithmetic(BigInt::one())
        } else {
            Arithmetic(-BigInt::one())
        }
    }

    fn normalize_mut(&mut self) {
        *self = Arithmetic(self.abs())
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
    use crate::arithmetic::traits::EGCD;

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
        let n_inv_expected = n.invert(&prime).unwrap();
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
