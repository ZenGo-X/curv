use std::cmp::Ordering;
use std::convert::TryFrom;
use std::sync::atomic;

use rug::Assign;
pub use rug::Integer as BigInt;
use rug::integer::Order;
use rug::ops::RemRounding;

use crate::arithmetic::traits::{self, BigInt as _};

use super::errors::*;

/// Big integer
///
/// Wraps underlying BigInt implementation (either GMP bindings or num-bigint), exposes only
/// very limited API that allows easily switching between implementations.
///
/// Set of traits implemented on BigInt remains the same regardless of underlying implementation.

impl traits::BigInt for BigInt {
    fn zero() -> Self {
        Self::new()
    }

    fn is_zero(&self) -> bool {
        self.cmp0() == Ordering::Equal
    }

    fn set_zero(&mut self) {
        self.assign(0);
    }

    fn one() -> Self {
        Self::from(1u8)
    }

    fn set_one(&mut self) {
        self.assign(1);
    }

    fn is_negative(&self) -> bool {
        self.cmp0() == Ordering::Less
    }

    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        self.set_bit(
            u32::try_from(bit).expect("There shouldn't be more than 2^32-1 bits"),
            bit_val,
        );
    }

    fn test_bit(&self, bit: usize) -> bool {
        self.get_bit(u32::try_from(bit).expect("There shouldn't be more than 2^32-1 bits"))
    }

    fn bit_length(&self) -> usize {
        usize::try_from(self.significant_bits()).expect("usize should always be bigger than u32")
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_digits(Order::MsfBe)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_digits(bytes, Order::MsfBe)
    }

    fn to_str_radix(&self, radix: u8) -> String {
        self.to_string_radix(i32::from(radix))
    }

    fn from_str_radix(s: &str, radix: u8) -> Result<Self, ParseBigIntError> {
        Self::from_str_radix(s, i32::from(radix)).map_err(|e| ParseBigIntError {
            reason: ParseErrorReason::Gmp(e),
            radix,
        })
    }

    fn zeroize(&mut self) {
        let mpz = unsafe { self.as_raw_mut().read() };
        let mut ptr = mpz.d.as_ptr();
        for _ in 0..mpz.alloc {
            unsafe {
                // SAFETY: The pointer is properly aligned and valid
                // because we got it from the gmp allocation which allocates limbs
                // The pointer is valid for writes because we assume `rug` handles it correctly.
                ptr.write_volatile(0);
                // SAFETY: The starting pointer is in bounds,
                // and the last pointer will point at a single byte past the last element.
                ptr = ptr.add(1)
            }
        }
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl traits::NumberTheoreticOps for BigInt {
    fn mod_pow(&self, exponent: &Self, modulo: &Self) -> Self {
        Self::from(
            self.pow_mod_ref(exponent, modulo)
                .expect("exponent must be non-negative"),
        )
    }

    fn mod_mul(&self, b: &Self, modulus: &Self) -> Self {
        BigInt::from(self * b).rem_floor(modulus)
    }

    fn mod_sub(&self, b: &Self, modulus: &Self) -> Self {
        BigInt::from(self - b).rem_floor(modulus)
    }

    fn mod_add(&self, b: &Self, modulus: &Self) -> Self {
        BigInt::from(self + b).rem_floor(modulus)
    }

    fn mod_inv(&self, modulo: &Self) -> Option<Self> {
        self.clone().invert(modulo).ok()
    }

    fn modulus(&self, modulus: &Self) -> Self {
        BigInt::from(self.rem_floor(modulus))
    }

    fn egcd(&self, b: &Self) -> (Self, Self, Self) {
        let (s, p, q) = self.clone().gcd_cofactors(b.clone(), Self::zero());
        (s, p, q)
    }

    fn gcd(&self, m: &Self) -> Self {
        self.clone().gcd(&m)
    }

    fn next_prime(&self) -> Self {
        BigInt::next_prime(self.clone())
    }

    fn is_probable_prime(&self, n: u32) -> bool {
        use rug::integer::IsPrime;
        self.is_probably_prime(n) != IsPrime::No
    }
}
