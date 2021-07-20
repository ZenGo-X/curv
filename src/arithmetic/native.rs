use core::convert::From;
use std::{cmp, ptr};
use std::convert::TryFrom;
use std::ops;

use num_bigint::BigInt as BN;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::{One, Zero};
use zeroize::Zeroize;

use super::errors::*;
use super::traits::{self, BigInt as _};

mod primes;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone)]
pub struct BigInt(num_bigint::BigInt);
/// Big integer
///
/// Wraps underlying BigInt implementation (either GMP bindings or num-bigint), exposes only
/// very limited API that allows easily switching between implementations.
///
/// Set of traits implemented on BigInt remains the same regardless of underlying implementation.
impl traits::BigInt for BigInt {
    fn zero() -> Self {
        Self(BN::zero())
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn set_zero(&mut self) {
        self.0.set_zero()
    }

    fn one() -> Self {
        Self(BN::one())
    }

    fn is_one(&self) -> bool {
        self.0.is_one()
    }

    fn set_one(&mut self) {
        self.0.set_one()
    }

    fn is_negative(&self) -> bool {
        self.0.sign() == Sign::Minus
    }

    fn set_bit(&mut self, bit: usize, bit_val: bool) {
        self.0
            .set_bit(u64::try_from(bit).expect("u64 >= usize"), bit_val);
    }
    fn test_bit(&self, bit: usize) -> bool {
        self.0.bit(u64::try_from(bit).expect("u64 >= usize"))
    }

    fn bit_length(&self) -> usize {
        usize::try_from(self.0.bits()).expect("there shouldn't be more than usize bits")
    }

    fn to_bytes(&self) -> Vec<u8> {
        let (_, bytes) = self.0.to_bytes_be();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(BN::from_bytes_be(Sign::Plus, bytes))
    }

    fn to_str_radix(&self, radix: u8) -> String {
        self.0.to_str_radix(radix.into())
    }
    fn from_str_radix(str: &str, radix: u8) -> Result<Self, ParseBigIntError> {
        BN::parse_bytes(str.as_bytes(), radix.into())
            .map(Self)
            .ok_or(ParseBigIntError {
                reason: ParseErrorReason::NumBigint,
                radix,
            })
    }
    fn zeroize(&mut self) {
        use core::sync::atomic;
        // Copy the inner so we can read the data inside
        let original = unsafe { ptr::read(self) };
        // Replace self with a zeroed integer.
        unsafe { ptr::write_volatile(self, Self::zero()) };
        let (mut sign, uint) = original.0.into_parts();
        // Zero out the temp sign in case it's a secret somehow
        unsafe { ptr::write_volatile(&mut sign, Sign::NoSign) };
        // zero out the bigint's data itself.
        // This is semi-UB because it's a repr(Rust) type, but because it's a single field we can assume it matches the wrapper.
        let mut data: Vec<usize> = unsafe { core::mem::transmute(uint) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
        data.zeroize();
    }
}

impl traits::NumberTheoreticOps for BigInt {
    fn mod_pow(&self, exponent: &Self, modulo: &Self) -> Self {
        Self(self.0.modpow(&exponent.0, &modulo.0))
    }

    fn mod_mul(&self, b: &Self, modulus: &Self) -> Self {
        Self((&self.0 * &b.0).mod_floor(&modulus.0))
    }

    fn mod_sub(&self, b: &Self, modulus: &Self) -> Self {
        Self((&self.0 - &b.0).mod_floor(&modulus.0))
    }

    fn mod_add(&self, b: &Self, modulus: &Self) -> Self {
        Self((&self.0 + &b.0).mod_floor(&modulus.0))
    }

    fn mod_inv(&self, modulo: &Self) -> Option<Self> {
        let (gcd, x, _) = self.egcd(modulo);
        // if the gcd of (a,m) is one then the x Bézout's coefficient is the mod inverse
        // a*x + m*y = gcd
        // a*x + m*y = 1
        //  a*x = 1 (mod m)
        // x = a^-1 (mod m)
        if gcd.is_one() {
            Some(x)
        } else {
            None
        }
    }

    fn modulus(&self, modulus: &Self) -> Self {
        Self(self.0.mod_floor(&modulus.0))
    }

    fn egcd(&self, b: &Self) -> (Self, Self, Self) {
        let extended = self.0.extended_gcd(&b.0);
        (Self(extended.gcd), Self(extended.x), Self(extended.y))
    }

    fn gcd(&self, m: &Self) -> Self {
        Self(self.0.gcd(&m.0))
    }

    fn next_prime(&self) -> Self {
        if self.0.sign() != Sign::Plus {
            return Self::from(2);
        }
        let uint = primes::next_prime(self.0.magnitude());
        Self(BN::from_biguint(Sign::Plus, uint))
    }

    fn is_probable_prime(&self, n: u32) -> bool {
        if self.0.sign() != Sign::Plus {
            false
        } else {
            primes::probably_prime(self.0.magnitude(), n as usize)
        }
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
}

crate::__bigint_impl_primitives_ops! {
    Shl shl u32,
    Shl shl i32,
    Shr shr u32,
    Shr shr i32,
}

crate::__bigint_impl_all_primitives_ops! {
    Div div,
    Rem rem,
    swap => Add add,
    swap => Sub sub,
    swap => Mul mul,
}

crate::__bigint_impl_fmt! {
    impl Binary for BigInt,
    impl Display for BigInt,
    impl LowerHex for BigInt,
    impl Octal for BigInt,
    impl UpperHex for BigInt,
}

crate::__bigint_impl_from! {
    i8 => From => from,
    u8 => From => from,
    i16 => From => from,
    u16 => From => from,
    i32 => From => from,
    u32 => From => from,
    i64 => From => from,
    u64 => From => from,
    i128 => From => from,
    u128 => From => from,
    isize => From => from,
    usize => From => from
}

crate::__bigint_impl_assigns! {
    AddAssign add_assign,
    AddAssign add_assign u64,
    AddAssign add_assign u32,
    AddAssign add_assign i32,
    AddAssign add_assign i64,
    BitAndAssign bitand_assign,
    BitOrAssign bitor_assign,
    BitXorAssign bitxor_assign,
    DivAssign div_assign,
    DivAssign div_assign u64,
    DivAssign div_assign u32,
    DivAssign div_assign i32,
    DivAssign div_assign i64,
    MulAssign mul_assign,
    MulAssign mul_assign u64,
    MulAssign mul_assign u32,
    MulAssign mul_assign i32,
    MulAssign mul_assign i64,
    RemAssign rem_assign,
    RemAssign rem_assign u64,
    RemAssign rem_assign u32,
    RemAssign rem_assign i32,
    RemAssign rem_assign i64,
    ShlAssign shl_assign usize,
    ShlAssign shl_assign u32,
    ShlAssign shl_assign i32,
    ShrAssign shr_assign usize,
    ShrAssign shr_assign u32,
    ShrAssign shr_assign i32,
    SubAssign sub_assign,
    SubAssign sub_assign u64,
    SubAssign sub_assign u32,
    SubAssign sub_assign i64,
    SubAssign sub_assign i32,
}

crate::__bigint_impl_cmp! {
    impl i32 with Self::from,
    impl i64 with Self::from,
    impl u32 with Self::from,
    impl u64 with Self::from,
}
