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

use super::errors::ParseBigIntError;

/// Reuse common traits from [num_integer] crate
pub use num_integer::{Integer, Roots};
/// Reuse common traits from [num_traits] crate
pub use num_traits::{One, Zero};

#[deprecated(
    since = "0.6.0",
    note = "BigInt now implements zeroize::Zeroize trait, you should use it instead"
)]
pub trait ZeroizeBN {
    fn zeroize_bn(&mut self);
}

/// Converts BigInt to/from various forms of representation.
pub trait Converter: Sized {
    /// Returns bytes representation of the number.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from(31).to_bytes(), &[31]);
    /// assert_eq!(BigInt::from(1_000_000).to_bytes(), &[15, 66, 64]);
    /// ```
    fn to_bytes(&self) -> Vec<u8>;
    /// Constructs BigInt from its byte representation
    ///
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from_bytes(&[15, 66, 64]), BigInt::from(1_000_000))
    /// ```
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Returns bytes representation of the number in an array with length chosen by the user
    /// if the array is larger than the bytes it pads it with zeros in the most significant bytes
    /// If the array is too small for the integer it returns None.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from(31).to_bytes_array(), Some([31]));
    /// assert_eq!(BigInt::from(31).to_bytes_array(), Some([0, 31]));
    /// assert_eq!(BigInt::from(1_000_000).to_bytes_array(), Some([15, 66, 64]));
    /// assert_eq!(BigInt::from(1_000_000).to_bytes_array::<2>(), None);
    /// assert_eq!(BigInt::from(1_000_000).to_bytes_array(), Some([0, 15, 66, 64]));
    /// ```
    fn to_bytes_array<const N: usize>(&self) -> Option<[u8; N]> {
        let bytes = self.to_bytes();
        if bytes.len() > N {
            return None;
        }
        let mut array = [0u8; N];
        array[N - bytes.len()..].copy_from_slice(&bytes);
        Some(array)
    }

    /// Converts BigInt to hex representation.
    ///
    /// If the number is negative, it will be serialized by absolute value, and minus character
    /// will be prepended to resulting string.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from(31).to_hex(), "1f");
    /// assert_eq!(BigInt::from(1_000_000).to_hex(), "f4240");
    /// ```
    fn to_hex(&self) -> String {
        self.to_str_radix(16)
    }
    /// Parses given hex string.
    ///
    /// Follows the same format as was described in [to_hex](Self::to_hex).
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from_hex("1f").unwrap(), BigInt::from(31));
    /// assert_eq!(BigInt::from_hex("-1f").unwrap(), BigInt::from(-31));
    /// assert_eq!(BigInt::from_hex("f4240").unwrap(), BigInt::from(1_000_000));
    /// assert_eq!(BigInt::from_hex("-f4240").unwrap(), BigInt::from(-1_000_000));
    /// ```
    fn from_hex(n: &str) -> Result<Self, ParseBigIntError> {
        Self::from_str_radix(n, 16)
    }

    /// Converts BigInt to radix representation.
    ///
    /// If the number is negative, it will be serialized by absolute value, and minus character
    /// will be prepended to resulting string.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from(31).to_str_radix(16), "1f");
    /// assert_eq!(BigInt::from(1_000_000).to_str_radix(16), "f4240");
    /// ```
    fn to_str_radix(&self, radix: u8) -> String;
    /// Parses given radix string.
    ///
    /// Radix must be in `[2; 36]` range. Otherwise, function will **panic**.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::{BigInt, Converter};
    /// assert_eq!(BigInt::from_str_radix("1f", 16).unwrap(), BigInt::from(31));
    /// assert_eq!(BigInt::from_str_radix("f4240", 16).unwrap(), BigInt::from(1_000_000));
    /// ```
    fn from_str_radix(s: &str, radix: u8) -> Result<Self, ParseBigIntError>;
}

/// Provides basic arithmetic operators for BigInt
///
/// Note that BigInt also implements std::ops::{Add, Mull, ...} traits, so you can
/// use them instead.
pub trait BasicOps {
    fn pow(&self, exponent: u32) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn abs(&self) -> Self;
}

/// Modular arithmetic for BigInt
pub trait Modulo: Sized {
    /// Calculates base^(exponent) (mod m)
    ///
    /// Exponent must not be negative. Function will panic otherwise.
    fn mod_pow(base: &Self, exponent: &Self, m: &Self) -> Self;
    /// Calculates a * b (mod m)
    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a - b (mod m)
    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a + b (mod m)
    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a^-1 (mod m). Returns None if `a` and `m` are not coprimes.
    fn mod_inv(a: &Self, m: &Self) -> Option<Self>;
    /// Calculates a mod m
    fn modulus(&self, modulus: &Self) -> Self;
}

/// Generating random BigInt
pub trait Samplable {
    /// Generates random number within `[0; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= 0`
    fn sample_below(upper: &Self) -> Self;
    /// Generates random number within `[lower; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= lower`
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    /// Generates random number within `(lower; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= lower`
    fn strict_sample_range(lower: &Self, upper: &Self) -> Self;
    /// Generates number within `[0; 2^bit_size)` range
    fn sample(bit_size: usize) -> Self;
    /// Generates number within `[2^(bit_size-1); 2^bit_size)` range
    fn strict_sample(bit_size: usize) -> Self;
}

/// Set of predicates allowing to examine BigInt
pub trait NumberTests {
    /// Returns `true` if `n` is zero
    ///
    /// Alternatively, [BasicOps::sign] method can be used to check sign of the number.
    fn is_zero(n: &Self) -> bool;
    /// Returns `true` if `n` is negative
    ///
    /// Alternatively, [BasicOps::sign] method can be used to check sign of the number.
    fn is_negative(n: &Self) -> bool;
}

/// Extended GCD algorithm
pub trait EGCD
where
    Self: Sized,
{
    /// For given a, b calculates gcd(a,b), p, q such as `gcd(a,b) = a*p + b*q`
    ///
    /// ## Example
    /// ```
    /// # use curv::arithmetic::*;
    /// let (a, b) = (BigInt::from(10), BigInt::from(15));
    /// let (s, p, q) = BigInt::egcd(&a, &b);
    /// assert_eq!(&s, &BigInt::from(5));
    /// assert_eq!(s, a*p + b*q);
    /// ```
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

/// Bits manipulation in BigInt
pub trait BitManipulation {
    /// Sets/unsets bit in the number
    ///
    /// ## Example
    /// ```
    /// # use curv::arithmetic::*;
    /// let mut n = BigInt::from(0b100);
    /// n.set_bit(3, true);
    /// assert_eq!(n, BigInt::from(0b1100));
    /// n.set_bit(0, true);
    /// assert_eq!(n, BigInt::from(0b1101));
    /// n.set_bit(2, false);
    /// assert_eq!(n, BigInt::from(0b1001));
    /// ```
    fn set_bit(&mut self, bit: usize, bit_val: bool);
    /// Tests if bit is set
    ///
    /// ```
    /// # use curv::arithmetic::*;
    /// let n = BigInt::from(0b101);
    /// assert_eq!(n.test_bit(3), false);
    /// assert_eq!(n.test_bit(2), true);
    /// assert_eq!(n.test_bit(1), false);
    /// assert_eq!(n.test_bit(0), true);
    /// ```
    fn test_bit(&self, bit: usize) -> bool;
    /// Length of the number in bits
    ///
    /// ```
    /// # use curv::arithmetic::*;
    /// assert_eq!(BigInt::from(0b1011).bit_length(), 4);
    /// ```
    fn bit_length(&self) -> usize;
}

#[deprecated(
    since = "0.6.0",
    note = "Use corresponding From<T> and TryFrom<T> traits implemented on BigInt"
)]
pub trait ConvertFrom<T> {
    fn _from(_: &T) -> Self;
}

/// Utilities for searching / testing prime numbers
pub trait Primes {
    /// Finds next prime number using probabilistic algorithms
    fn next_prime(&self) -> Self;
    /// Probabilistically determine whether number is prime
    ///
    /// If number is prime, `is_probable_prime` always returns true. If number is composite,
    /// `is_probable_prime` probably return false. The probability of returning true for a randomly
    /// chosen non-prime is at most 4^(-reps).
    fn is_probable_prime(&self, n: u32) -> bool;
}
