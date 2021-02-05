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

use super::errors::ParseBigIntFromHexError;

/// Reuse common traits from [num_traits] crate
pub use num_traits::{One, Zero};

#[deprecated(
    since = "0.6.0",
    note = "BigInt now implements zeroize::Zeroize trait, you should use it instead"
)]
pub trait ZeroizeBN {
    fn zeroize_bn(&mut self);
}
pub trait Converter: Sized {
    fn to_vec(&self) -> Vec<u8>;
    fn to_hex(&self) -> String;
    fn from_hex(n: &str) -> Result<Self, ParseBigIntFromHexError>;
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
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self;
    /// Returns b = a^-1 (mod m). Returns None if `a` and `modulus` are not coprimes.
    fn mod_inv(a: &Self, m: &Self) -> Option<Self>;
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
    fn is_zero(n: &Self) -> bool;
    fn is_even(n: &Self) -> bool;
    fn is_negative(n: &Self) -> bool;
}

/// Extended GCD algorithm
pub trait EGCD
where
    Self: Sized,
{
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

/// Bits manipulation in BigInt
pub trait BitManipulation {
    fn set_bit(&mut self, bit: usize, bit_val: bool);
    fn test_bit(&self, bit: usize) -> bool;
    fn bit_length(&self) -> usize;
}

#[deprecated(
    since = "0.6.0",
    note = "Use corresponding From<T> and TryFrom<T> traits implemented on BigInt"
)]
pub trait ConvertFrom<T> {
    fn _from(_: &T) -> Self;
}
