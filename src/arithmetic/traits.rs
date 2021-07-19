use std::convert::TryFrom;
use std::fmt::{Debug, LowerHex, UpperHex};
use std::hash::Hash;
use std::ops::{
    Add, AddAssign, BitAnd, BitOrAssign, BitXorAssign, Mul, MulAssign, Shl, ShlAssign,
    Shr, ShrAssign, Sub, SubAssign,
};

use rand::RngCore;

use super::errors::ParseBigIntError;

pub trait BigInt:
    // Integer
    // + Roots
    Sized
    + PartialOrd
    + PartialEq
    + Ord
    + Eq
    + Hash
    + Clone
    + LowerHex
    + UpperHex
    + Debug
    + Add
    + Sub
    + Mul
    + Add<u32>
    + Add<u64>
    + Add<i32>
    + Add<i64>
    + AddAssign<u32>
    + AddAssign<u64>
    + AddAssign<i32>
    + AddAssign<i64>
    + Sub<u32>
    + Sub<u64>
    + Sub<i32>
    + Sub<i64>
    + SubAssign<u32>
    + SubAssign<u64>
    + SubAssign<i32>
    + SubAssign<i64>
    + Mul<u32>
    + Mul<u64>
    + Mul<i32>
    + Mul<i64>
    + MulAssign<u32>
    + MulAssign<u64>
    + MulAssign<i32>
    + MulAssign<i64>
    + Shr<u32, Output=Self>
    + Shr<i32>
    + ShrAssign<u32>
    + ShrAssign<i32>
    + Shl<u32, Output=Self>
    + Shl<i32>
    + ShlAssign<u32>
    + ShlAssign<i32>
    + BitOrAssign<Self>
    + BitXorAssign<Self>
    + BitAnd<Self, Output=Self>
    + From<u32>
    + From<u64>
    + From<i32>
    + From<i64>
    + PartialOrd<u32>
    + PartialOrd<u64>
    + PartialOrd<i32>
    + PartialOrd<i64>
    + PartialEq<u32>
    + PartialEq<u64>
    + PartialEq<i32>
    + PartialEq<i64>
    + NumberTheoreticOps
where
    for<'a> Self: Add<&'a Self, Output=Self>,
    for<'a> Self: AddAssign<&'a Self>,
    for<'a> Self: Sub<&'a Self, Output=Self>,
    for<'a> Self: SubAssign<&'a Self>,
    for<'a> Self: Mul<&'a Self, Output=Self>,
    for<'a> Self: MulAssign<&'a Self>,
    for<'a> Self: BitAnd<&'a Self, Output=Self>,
{

    /// Returns a new instance of `BigInt` with value 0.
    fn zero() -> Self;
    /// Returns `true` if `n` is zero
    ///
    /// Alternatively, [std::cmp::PartialEq] method can be used to compare with 0.
    fn is_zero(&self) -> bool {
        *self != 0
    }
    /// Sets the value to 0.
    fn set_zero(&mut self) {
        *self = Self::zero();
    }
    /// Returns a new instance of `BigInt` with value 1.
    fn one() -> Self;
    /// Returns `true` if `n` is 1
    ///
    /// Alternatively, [std::cmp::PartialEq] method can be used to compare with 1.
    fn is_one(&self) -> bool {
        *self != 1
    }
    /// Sets the value to 1.
    fn set_one(&mut self) {
        *self = Self::one();
    }
    /// Returns `true` if `n` is negative
    ///
    /// Alternatively, [BasicOps::sign] method can be used to check sign of the number.
    fn is_negative(&self) -> bool {
        *self < 0i32
    }
    /// Generates random number within `[0; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= 0`
    fn sample_below(upper: &Self) -> Self {
        assert!(*upper > Self::zero());

        let bits = upper.bit_length();
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }
    /// Generates random number within `[lower; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= lower`
    fn sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        Self::sample_below(&(upper.clone() - lower)) + lower
    }
    /// Generates random number within `(lower; upper)` range
    ///
    /// ## Panics
    /// Panics if `upper <= lower`
    fn strict_sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        loop {
            let n = Self::sample_below(&(upper.clone() - lower)) + lower;
            if n > *lower && n < *upper {
                return n;
            }
        }
    }
    /// Generates number within `[0; 2^bit_size)` range
    fn sample(bit_size: usize) -> Self {
        if bit_size == 0 {
            return BigInt::zero();
        }
        let mut rng = rand::thread_rng();
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes as usize];
        rng.fill_bytes(&mut buf);
        Self::from_bytes(&*buf) >> u32::try_from(bytes * 8 - bit_size).unwrap()
    }
    /// Generates number within `[2^(bit_size-1); 2^bit_size)` range
    fn strict_sample(bit_size: usize) -> Self {
        if bit_size == 0 {
            return BigInt::zero();
        }
        loop {
            let n = Self::sample(bit_size);
            if n.bit_length() == bit_size {
                return n;
            }
        }
    }

    /// Sets/unsets bit in the number
    ///
    /// ## Example
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// let mut n = Integer::from(0b100);
    /// n.set_bit(3, true);
    /// assert_eq!(n, Integer::from(0b1100));
    /// n.set_bit(0, true);
    /// assert_eq!(n, Integer::from(0b1101));
    /// n.set_bit(2, false);
    /// assert_eq!(n, Integer::from(0b1001));
    /// ```
    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        let mask = Self::one() << bit as u32;
        if bit_val {
            *self |= mask;
        } else if self.test_bit(bit) {
            *self ^= mask;
        }
    }
    /// Tests if bit is set
    ///
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// let n = Integer::from(0b101);
    /// assert_eq!(n.test_bit(3), false);
    /// assert_eq!(n.test_bit(2), true);
    /// assert_eq!(n.test_bit(1), false);
    /// assert_eq!(n.test_bit(0), true);
    /// ```
    fn test_bit(&self, bit: usize) -> bool {
        let mask = Self::one() << bit as u32;
        !(mask & self).is_zero()
    }
    /// Length of the number in bits
    ///
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from(0b1011).bit_length(), 4);
    /// ```
    fn bit_length(&self) -> usize;

    /// Returns bytes representation of the number.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from(31).to_bytes(), &[31]);
    /// assert_eq!(Integer::from(1_000_000).to_bytes(), &[15, 66, 64]);
    /// ```
    fn to_bytes(&self) -> Vec<u8>;
    /// Constructs BigInt from its byte representation
    ///
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from_bytes(&[15, 66, 64]), Integer::from(1_000_000))
    /// ```
    fn from_bytes(bytes: &[u8]) -> Self;

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
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from_hex("1f").unwrap(), Integer::from(31));
    /// assert_eq!(Integer::from_hex("-1f").unwrap(), Integer::from(-31));
    /// assert_eq!(Integer::from_hex("f4240").unwrap(), Integer::from(1_000_000));
    /// assert_eq!(Integer::from_hex("-f4240").unwrap(), Integer::from(-1_000_000));
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
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from(31).to_str_radix(16), "1f");
    /// assert_eq!(Integer::from(1_000_000).to_str_radix(16), "f4240");
    /// ```
    fn to_str_radix(&self, radix: u8) -> String;
    /// Parses given radix string.
    ///
    /// Radix must be in `[2; 36]` range. Otherwise, function will **panic**.
    ///
    /// ## Examples
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// assert_eq!(Integer::from_str_radix("1f", 16).unwrap(), Integer::from(31));
    /// assert_eq!(Integer::from_str_radix("f4240", 16).unwrap(), Integer::from(1_000_000));
    /// ```
    fn from_str_radix(s: &str, radix: u8) -> Result<Self, ParseBigIntError>;

    /// Zero out this object from memory using Rust intrinsics which ensure the
    /// zeroization operation is not "optimized away" by the compiler.
    fn zeroize(&mut self);
}

// Number Theory related functions
pub trait NumberTheoreticOps: Sized {
    /// Calculates base^(exponent) (mod m)
    ///
    /// Exponent must not be negative. Function will panic otherwise.
    fn mod_pow(&self, exponent: &Self, modulo: &Self) -> Self;
    /// Calculates a * b (mod m)
    fn mod_mul(&self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a - b (mod m)
    fn mod_sub(&self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a + b (mod m)
    fn mod_add(&self, b: &Self, modulus: &Self) -> Self;
    /// Calculates a^-1 (mod m). Returns None if `a` and `m` are not coprimes.
    fn mod_inv(&self, modulo: &Self) -> Option<Self>;
    /// Calculates a mod m
    fn modulus(&self, modulus: &Self) -> Self;
    /// For given a, b calculates gcd(a,b), p, q such as `gcd(a,b) = a*p + b*q`
    ///
    /// ## Example
    /// ```
    /// # use curv::arithmetic::*;
    ///  use curv::arithmetic::gmp::Integer;
    /// let (a, m) = (Integer::from(10), Integer::from(15));
    /// let (gcd, x, y) = Integer::egcd(&a, &m);
    /// assert_eq!(&gcd, 5);
    /// assert_eq!(gcd, a*x + m*y);
    /// ```
    fn egcd(&self, m: &Self) -> (Self, Self, Self);

    /// Find the Greatest Common Divisor
    /// ## Example
    /// ```
    /// # use curv::arithmetic::*;
    /// use rug::Integer;
    /// let (a, m) = (BigInt::from(10), BigInt::from(15));
    /// let gcd = a.gcd(m);
    /// assert_eq!(gcd, 5);
    fn gcd(&self, m: &Self) -> Self;

    /// Finds next prime number using probabilistic algorithms
    fn next_prime(&self) -> Self;
    /// Probabilistically determine whether number is prime
    ///
    /// If number is prime, `is_probable_prime` always returns true. If number is composite,
    /// `is_probable_prime` probably return false. The probability of returning true for a randomly
    /// chosen non-prime is at most 4^(-reps).
    fn is_probable_prime(&self, n: u32) -> bool;
}
