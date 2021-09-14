use std::convert::{TryFrom, TryInto};
use std::{fmt, ops};

use num_traits::Signed;

use super::errors::*;
use super::traits::*;

use num_bigint::BigInt as BN;
use num_bigint::Sign;

mod primes;
mod ring_algorithms;

/// Big integer
///
/// Wraps underlying BigInt implementation (either GMP bindings or num-bigint), exposes only
/// very limited API that allows easily switching between implementations.
///
/// Set of traits implemented on BigInt remains the same regardless of underlying implementation.
#[derive(PartialOrd, PartialEq, Ord, Eq, Clone)]
pub struct BigInt {
    num: BN,
}

impl BigInt {
    fn inner_ref(&self) -> &BN {
        &self.num
    }
    fn inner_mut(&mut self) -> &mut BN {
        &mut self.num
    }
    fn into_inner(self) -> BN {
        self.num
    }
}

#[allow(deprecated)]
impl ZeroizeBN for BigInt {
    fn zeroize_bn(&mut self) {
        zeroize::Zeroize::zeroize(self)
    }
}

impl zeroize::Zeroize for BigInt {
    fn zeroize(&mut self) {
        use std::{ptr, sync::atomic};
        unsafe { ptr::write_volatile(&mut self.num, Zero::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Converter for BigInt {
    fn to_bytes(&self) -> Vec<u8> {
        let (_sign, bytes) = self.num.to_bytes_be();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        BN::from_bytes_be(Sign::Plus, bytes).wrap()
    }

    fn to_hex(&self) -> String {
        self.num.to_str_radix(16)
    }

    fn from_hex(n: &str) -> Result<Self, ParseBigIntError> {
        BN::parse_bytes(n.as_bytes(), 16)
            .map(Wrap::wrap)
            .ok_or(ParseBigIntError {
                reason: ParseErrorReason::NumBigint,
                radix: 16,
            })
    }

    fn to_str_radix(&self, radix: u8) -> String {
        self.num.to_str_radix(radix.into())
    }

    fn from_str_radix(str: &str, radix: u8) -> Result<Self, ParseBigIntError> {
        BN::parse_bytes(str.as_bytes(), radix.into())
            .map(Wrap::wrap)
            .ok_or(ParseBigIntError {
                reason: ParseErrorReason::NumBigint,
                radix: radix.into(),
            })
    }
}

impl num_traits::Num for BigInt {
    type FromStrRadixErr = ParseBigIntError;

    fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        <Self as Converter>::from_str_radix(str, radix.try_into().unwrap())
    }
}

crate::__bigint_impl_from! { u32, i32, u64 }

impl From<u16> for BigInt {
    fn from(n: u16) -> Self {
        BigInt::from(u64::from(n))
    }
}

impl BasicOps for BigInt {
    fn pow(&self, exponent: u32) -> Self {
        self.num.pow(exponent).wrap()
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
        self.num.abs().wrap()
    }
}

impl Primes for BigInt {
    fn next_prime(&self) -> BigInt {
        if self.num.sign() != Sign::Plus {
            return BigInt::from(2);
        }
        let uint = primes::next_prime(self.num.magnitude());
        BN::from_biguint(Sign::Plus, uint).wrap()
    }

    fn is_probable_prime(&self, n: u32) -> bool {
        if self.num.sign() != Sign::Plus {
            false
        } else {
            primes::probably_prime(self.num.magnitude(), n as usize)
        }
    }
}

impl Modulo for BigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.num.modpow(&exponent.num, &modulus.num).wrap()
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.num.mod_floor(&modulus.num) * b.num.mod_floor(&modulus.num))
            .mod_floor(&modulus.num)
            .wrap()
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.num.mod_floor(&modulus.num);
        let b_m = b.num.mod_floor(&modulus.num);

        let sub_op = a_m - b_m + &modulus.num;
        sub_op.mod_floor(&modulus.num).wrap()
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.num.mod_floor(&modulus.num) + b.num.mod_floor(&modulus.num))
            .mod_floor(&modulus.num)
            .wrap()
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Option<Self> {
        ring_algorithms::modulo_inverse(a, modulus).map(|inv| inv.modulus(modulus))
    }

    fn modulus(&self, modulus: &Self) -> Self {
        let n = self % modulus;
        if n.num.sign() == Sign::Minus {
            modulus + n
        } else {
            n
        }
    }
}

impl BitManipulation for BigInt {
    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        let mask = BigInt::one() << bit;
        if bit_val {
            *self |= mask;
        } else if self.test_bit(bit) {
            *self ^= mask;
        }
    }

    fn test_bit(&self, bit: usize) -> bool {
        let mask = BigInt::one() << bit;
        !(self & mask).is_zero()
    }

    fn bit_length(&self) -> usize {
        self.num.bits() as usize
    }
}

impl NumberTests for BigInt {
    fn is_zero(n: &Self) -> bool {
        matches!(n.num.sign(), Sign::NoSign)
    }

    fn is_negative(n: &Self) -> bool {
        matches!(n.num.sign(), Sign::Minus)
    }
}

impl EGCD for BigInt {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        ring_algorithms::normalized_extended_euclidian_algorithm(a, b)
    }
}

impl Integer for BigInt {
    fn div_floor(&self, other: &Self) -> Self {
        self.num.div_floor(&other.num).wrap()
    }

    fn mod_floor(&self, other: &Self) -> Self {
        self.num.mod_floor(&other.num).wrap()
    }

    fn div_ceil(&self, other: &Self) -> Self {
        self.num.div_ceil(&other.num).wrap()
    }

    fn gcd(&self, other: &Self) -> Self {
        self.num.gcd(&other.num).wrap()
    }

    fn lcm(&self, other: &Self) -> Self {
        self.num.lcm(&other.num).wrap()
    }

    fn gcd_lcm(&self, other: &Self) -> (Self, Self) {
        let (n, m) = self.num.gcd_lcm(&other.num);
        (n.wrap(), m.wrap())
    }

    fn divides(&self, other: &Self) -> bool {
        self.num.divides(&other.num)
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.num.is_multiple_of(&other.num)
    }

    fn is_even(&self) -> bool {
        self.num.is_even()
    }

    fn is_odd(&self) -> bool {
        self.num.is_odd()
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (n, m) = self.num.div_rem(&other.num);
        (n.wrap(), m.wrap())
    }

    fn div_mod_floor(&self, other: &Self) -> (Self, Self) {
        let (n, m) = self.num.div_mod_floor(&other.num);
        (n.wrap(), m.wrap())
    }

    fn next_multiple_of(&self, other: &Self) -> Self
    where
        Self: Clone,
    {
        self.num.next_multiple_of(&other.num).wrap()
    }

    fn prev_multiple_of(&self, other: &Self) -> Self
    where
        Self: Clone,
    {
        self.num.prev_multiple_of(&other.num).wrap()
    }
}

impl Roots for BigInt {
    fn nth_root(&self, n: u32) -> Self {
        self.num.nth_root(n).wrap()
    }

    fn sqrt(&self) -> Self {
        self.num.sqrt().wrap()
    }

    fn cbrt(&self) -> Self {
        self.num.cbrt().wrap()
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.num.fmt(f)
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.num.fmt(f)
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
        self.num.neg().wrap()
    }
}
impl ops::Neg for &BigInt {
    type Output = BigInt;
    fn neg(self) -> Self::Output {
        (&self.num).neg().wrap()
    }
}

impl num_traits::Zero for BigInt {
    fn zero() -> Self {
        BN::zero().wrap()
    }
    fn is_zero(&self) -> bool {
        matches!(self.num.sign(), Sign::NoSign)
    }
}

impl num_traits::One for BigInt {
    fn one() -> Self {
        BN::one().wrap()
    }
}

macro_rules! impl_try_from {
    ($($primitive:ty),*$(,)?) => {
        $(
        impl TryFrom<&BigInt> for $primitive {
            type Error = TryFromBigIntError;

            fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
                TryFrom::<&BN>::try_from(&value.num)
                    .map_err(|_| TryFromBigIntError { type_name: stringify!($primitive) })
            }
        }
        )*
    };
}

impl_try_from! { u64, i64 }

#[allow(deprecated)]
impl ConvertFrom<BigInt> for u64 {
    fn _from(x: &BigInt) -> u64 {
        let opt_x: u64 = (&x.num).try_into().unwrap();
        opt_x
    }
}

/// Internal helper trait. Creates short-hand for wrapping Mpz into BigInt.
trait Wrap {
    fn wrap(self) -> BigInt;
}
impl Wrap for BN {
    fn wrap(self) -> BigInt {
        BigInt { num: self }
    }
}
