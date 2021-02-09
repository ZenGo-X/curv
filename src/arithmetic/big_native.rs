use std::convert::TryFrom;
use std::ops;

use num_integer::Integer;
use num_traits::Signed;
use serde::{Deserialize, Serialize};

use super::errors::*;
use super::traits::{Sign as S, *};

use num_bigint::BigInt as BN;
use num_bigint::Sign;

#[derive(PartialOrd, PartialEq, Ord, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
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
    fn to_vec(&self) -> Vec<u8> {
        let (_sign, bytes) = self.num.to_bytes_be();
        bytes
    }

    fn to_hex(&self) -> String {
        self.num.to_str_radix(16)
    }

    fn from_hex(n: &str) -> Result<Self, ParseBigIntFromHexError> {
        BN::parse_bytes(n.as_bytes(), 16)
            .map(Wrap::wrap)
            .ok_or(ParseFromHexReason::Native.into())
    }
}

impl From<&[u8]> for BigInt {
    fn from(bytes: &[u8]) -> Self {
        BN::from_bytes_be(Sign::Plus, bytes).wrap()
    }
}

crate::__bigint_impl_from! { u32, i32, u64 }

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

    fn sign(&self) -> S {
        match self.gmp.sign() {
            Sign::Minus => S::Negative,
            Sign::NoSign => S::Zero,
            Sign::Plus => S::Positive,
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
        ring_algorithm::modulo_inverse(a.clone(), modulus.clone())
    }

    fn modulus(&self, modulus: &Self) -> Self {
        (&self.num % &modulus.num).wrap()
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
}

crate::__bigint_impl_assigns! {
    AddAssign add_assign,
    BitAndAssign bitand_assign,
    BitOrAssign bitor_assign,
    BitXorAssign bitxor_assign,
    DivAssign div_assign,
    MulAssign mul_assign,
    RemAssign rem_assign,
    ShlAssign shl_assign usize,
    ShrAssign shr_assign usize,
    SubAssign sub_assign,
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

impl ring_algorithm::RingNormalize for BigInt {
    fn leading_unit(&self) -> Self {
        match self.num.sign() {
            Sign::Minus => -BigInt::one(),
            _ => BigInt::one(),
        }
    }

    fn normalize_mut(&mut self) {
        self.num = self.num.abs();
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

/// Internal helper trait. Creates short-hand for wrapping Mpz into BigInt.
trait Wrap {
    fn wrap(self) -> BigInt;
}
impl Wrap for BN {
    fn wrap(self) -> BigInt {
        BigInt { num: self }
    }
}
