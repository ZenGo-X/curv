use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{error::ZeroScalarError, format::ScalarFormat, ScalarZ};

/// Scalar value in a prime field that _guaranteed_ to be non zero
///
/// ## Security
///
/// Non-zero scalars are preferred to be used in cryptographic algorithms. Lack of checking whether
/// computation on field scalars results into zero scalar might lead to vulnerability. Using `Scalar<E>`
/// ensures you and reviewers that check on scalar not being zero was made.
///
/// ## Guarantees
///
/// * Belongs to the curve prime field
///
///   Denoting group order as `n`, any instance `s` of `Scalar<E>` is guaranteed to be less than `n`:
///   `s < n`
/// * Not a zero
///
///   Any instance `s` of `Scalar<E>` is guaranteed to be more than zero: `s > 0`
///
/// Combining two rules above, any instance `s` of `Scalar<E>` is guaranteed to be: `0 < s < n`.
///
/// ## Arithmetic
///
/// Supported operations:
/// * Unary: you can [invert](Self::invert) and negate a scalar by modulo of prime field
/// * Binary: you can add, subtract, and multiply two points
///
/// Addition or subtraction of two (even non-zero) scalars might result into zero
/// scalar, so these operations output [ScalarZ]. Use [ensure_nonzero](ScalarZ::ensure_nonzero) method
/// to ensure that computation doesn't produce zero scalar:
///
/// ```rust
/// # use curv::elliptic::curves::{ScalarZ, Scalar, Secp256k1};
/// let a = Scalar::<Secp256k1>::random();
/// let b = Scalar::<Secp256k1>::random();
/// let result: ScalarZ<Secp256k1> = a + b;
/// let non_zero_result: Option<Scalar<Secp256k1>> = result.ensure_nonzero();
/// ```
///
/// Multiplication of two nonzero scalars is always nonzero scalar (as scalar is by prime modulo):
///
/// ```rust
/// # use curv::elliptic::curves::{ScalarZ, Scalar, Secp256k1};
/// let a = Scalar::<Secp256k1>::random();
/// let b = Scalar::<Secp256k1>::random();
/// let result: Scalar<Secp256k1> = a * b;
/// ```
#[derive(Serialize, Deserialize)]
#[serde(try_from = "ScalarFormat<E>", into = "ScalarFormat<E>", bound = "")]
pub struct Scalar<E: Curve> {
    raw_scalar: E::Scalar,
}

impl<E: Curve> Scalar<E> {
    /// Samples a random non-zero scalar
    pub fn random() -> Self {
        loop {
            if let Some(scalar) = ScalarZ::from_raw(E::Scalar::random()).ensure_nonzero() {
                break scalar;
            }
        }
    }

    /// Returns modular multiplicative inverse of the scalar
    ///
    /// Inverse of non-zero scalar is always defined in a prime field, and inverted scalar is also
    /// guaranteed to be non-zero.
    pub fn invert(&self) -> Self {
        self.as_raw()
            .invert()
            .map(|s| Scalar::from_raw(s).expect("inversion must be non-zero"))
            .expect("non-zero scalar must have corresponding inversion")
    }

    /// Returns a curve order
    pub fn group_order() -> &'static BigInt {
        E::Scalar::group_order()
    }

    /// Converts a scalar to [BigInt]
    pub fn to_bigint(&self) -> BigInt {
        self.as_raw().to_bigint()
    }

    /// Constructs a scalar from [BigInt] or returns error if it's zero
    pub fn from_bigint(n: &BigInt) -> Result<Self, ZeroScalarError> {
        Self::from_raw(E::Scalar::from_bigint(n))
    }

    /// Constructs a `Scalar<E>` from low-level [ECScalar] implementor
    ///
    /// Returns error if scalar is zero
    ///
    /// Typically, you don't need to use this constructor. See [random](Self::random),
    /// [from_bigint](Self::from_bigint) constructors, and `From<T>`, `TryFrom<T>` traits implemented
    /// for `Scalar<E>`.
    ///
    /// [ECScalar]: crate::elliptic::curves::ECScalar
    pub fn from_raw(raw_scalar: E::Scalar) -> Result<Self, ZeroScalarError> {
        if raw_scalar.is_zero() {
            Err(ZeroScalarError(()))
        } else {
            Ok(Self { raw_scalar })
        }
    }

    /// Constructs a `Scalar<E>` from low-level [ECScalar] implementor
    ///
    /// # Safety
    ///
    /// This function will not perform any checks against the scalar. You must guarantee that scalar
    /// is not zero. To perform this check, you may use [ECScalar::is_zero][is_zero] method.
    ///
    /// [is_zero]: crate::elliptic::curves::ECScalar::is_zero
    pub unsafe fn from_raw_unchecked(raw_scalar: E::Scalar) -> Self {
        Self { raw_scalar }
    }

    /// Returns a reference to low-level scalar implementation
    ///
    /// Typically, you don't need to work with `ECScalar` trait directly. `Scalar<E>` wraps `ECScalar`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, etc. If you believe that some functionality is missing, please
    /// [open an issue](https://github.com/ZenGo-X/curv).
    pub fn as_raw(&self) -> &E::Scalar {
        &self.raw_scalar
    }

    /// Converts a scalar into inner low-level scalar implementation
    ///
    /// Typically, you don't need to work with `ECScalar` trait directly. `Scalar<E>` wraps `ECScalar`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, etc. If you believe that some functionality is missing, please
    /// [open an issue](https://github.com/ZenGo-X/curv).
    pub fn into_raw(self) -> E::Scalar {
        self.raw_scalar
    }
}

impl<E: Curve> Clone for Scalar<E> {
    fn clone(&self) -> Self {
        // Safety: `self` is guaranteed to be non-zero
        unsafe { Scalar::from_raw_unchecked(self.as_raw().clone()) }
    }
}

impl<E: Curve> fmt::Debug for Scalar<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_raw().fmt(f)
    }
}

impl<E: Curve> PartialEq for Scalar<E> {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> PartialEq<ScalarZ<E>> for Scalar<E> {
    fn eq(&self, other: &ScalarZ<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> TryFrom<u16> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: u16) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(&BigInt::from(n))
    }
}

impl<E: Curve> TryFrom<u32> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: u32) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(&BigInt::from(n))
    }
}

impl<E: Curve> TryFrom<u64> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: u64) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(&BigInt::from(n))
    }
}

impl<E: Curve> TryFrom<i32> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: i32) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(&BigInt::from(n))
    }
}

impl<E: Curve> TryFrom<&BigInt> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: &BigInt) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(n)
    }
}

impl<E: Curve> TryFrom<BigInt> for Scalar<E> {
    type Error = ZeroScalarError;
    fn try_from(n: BigInt) -> Result<Self, ZeroScalarError> {
        Self::from_bigint(&n)
    }
}
