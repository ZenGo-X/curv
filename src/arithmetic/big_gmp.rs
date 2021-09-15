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

use std::convert::{TryFrom, TryInto};
use std::sync::atomic;
use std::{fmt, ops, ptr};

use gmp::mpz::Mpz;
use gmp::sign::Sign;
use num_traits::{One, Zero};
use zeroize::Zeroize;

use super::errors::*;
use super::traits::*;

type BN = Mpz;

/// Big integer
///
/// Wraps underlying BigInt implementation (either GMP bindings or num-bigint), exposes only
/// very limited API that allows easily switching between implementations.
///
/// Set of traits implemented on BigInt remains the same regardless of underlying implementation.
#[derive(PartialOrd, PartialEq, Ord, Eq, Clone)]
pub struct BigInt {
    gmp: Mpz,
}

impl BigInt {
    fn inner_ref(&self) -> &Mpz {
        &self.gmp
    }
    fn inner_mut(&mut self) -> &mut Mpz {
        &mut self.gmp
    }
    fn into_inner(self) -> Mpz {
        self.gmp
    }
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
    fn to_bytes(&self) -> Vec<u8> {
        (&self.gmp).into()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Mpz::from(bytes).wrap()
    }

    fn to_hex(&self) -> String {
        self.gmp.to_str_radix(16)
    }

    fn from_hex(value: &str) -> Result<BigInt, ParseBigIntError> {
        Mpz::from_str_radix(value, 16)
            .map(Wrap::wrap)
            .map_err(|e| ParseBigIntError {
                reason: ParseErrorReason::Gmp(e),
                radix: 16,
            })
    }

    fn to_str_radix(&self, radix: u8) -> String {
        self.gmp.to_str_radix(radix)
    }

    fn from_str_radix(str: &str, radix: u8) -> Result<Self, ParseBigIntError> {
        Mpz::from_str_radix(str, radix)
            .map(Wrap::wrap)
            .map_err(|e| ParseBigIntError {
                reason: ParseErrorReason::Gmp(e),
                radix: radix.into(),
            })
    }
}

impl num_traits::Num for BigInt {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(str: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        <Self as Converter>::from_str_radix(str, radix.try_into().unwrap())
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

impl Primes for BigInt {
    fn next_prime(&self) -> Self {
        self.gmp.nextprime().wrap()
    }

    fn is_probable_prime(&self, n: u32) -> bool {
        use gmp::mpz::ProbabPrimeResult::*;
        match self.gmp.probab_prime(n as i32) {
            Prime | ProbablyPrime => true,
            NotPrime => false,
        }
    }
}

impl Modulo for BigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        assert!(exponent >= &BigInt::zero(), "exponent must be non-negative");
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

impl NumberTests for BigInt {
    fn is_zero(me: &Self) -> bool {
        me.gmp.is_zero()
    }
    fn is_negative(me: &Self) -> bool {
        matches!(me.gmp.sign(), Sign::Negative)
    }
}

impl EGCD for BigInt {
    #[allow(clippy::many_single_char_names)]
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

impl Integer for BigInt {
    fn div_floor(&self, other: &Self) -> Self {
        self.gmp.div_floor(&other.gmp).wrap()
    }

    fn mod_floor(&self, other: &Self) -> Self {
        self.gmp.mod_floor(&other.gmp).wrap()
    }

    fn gcd(&self, other: &Self) -> Self {
        self.gmp.gcd(&other.gmp).wrap()
    }

    fn lcm(&self, other: &Self) -> Self {
        self.gmp.lcm(&other.gmp).wrap()
    }

    fn divides(&self, other: &Self) -> bool {
        self.gmp.divides(&other.gmp)
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.gmp.is_multiple_of(&other.gmp)
    }

    fn is_even(&self) -> bool {
        self.gmp.is_multiple_of(&Mpz::from(2))
    }

    fn is_odd(&self) -> bool {
        !self.gmp.is_multiple_of(&Mpz::from(2))
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let n = self / other;
        let m = self % other;
        (n, m)
    }
}

impl Roots for BigInt {
    fn nth_root(&self, n: u32) -> Self {
        self.gmp.root(n).wrap()
    }

    fn sqrt(&self) -> Self {
        self.gmp.sqrt().wrap()
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.gmp.fmt(f)
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.gmp.fmt(f)
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

crate::__bigint_impl_ops! {
    Add add,
    Sub sub,
    Mul mul,
    Div div,
    Rem rem,
    BitAnd bitand,
    BitXor bitxor,
    Shl shl usize,
    Shr shr usize,

    Add add u64 [swap],
    Sub sub u64 [swap],
    Mul mul u64 [swap],
    Div div u64,
    Rem rem u64,
}

crate::__bigint_impl_assigns! {
    AddAssign add_assign,
    AddAssign add_assign u64,
    BitAndAssign bitand_assign,
    BitOrAssign bitor_assign,
    BitXorAssign bitxor_assign,
    DivAssign div_assign,
    DivAssign div_assign u64,
    MulAssign mul_assign,
    MulAssign mul_assign u64,
    RemAssign rem_assign,
    RemAssign rem_assign u64,
    ShlAssign shl_assign usize,
    ShrAssign shr_assign usize,
    SubAssign sub_assign,
    SubAssign sub_assign u64,
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

crate::__bigint_impl_from! { u32, i32, u64 }

impl From<u16> for BigInt {
    fn from(n: u16) -> Self {
        BigInt::from(u64::from(n))
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
