use std::fmt;

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::traits::{Curve, ECScalar};
use crate::BigInt;

use super::{format::ScalarFormat, Scalar};

/// Scalar value in a prime field that **might be zero**
///
/// ## Security
///
/// Mistakenly used zero scalar might break security of cryptographic algorithm. It's preferred to
/// use `Scalar<E>`[Scalar] that's guaranteed to be non-zero. Use [ensure_nonzero](ScalarZ::ensure_nonzero)
/// to convert `ScalarZ` into `Scalar`.
///
/// ## Guarantees
///
/// * Modulus group order
///
///   Denoting [group order](Self::group_order) as `n`, any instance `s` of `ScalarZ<E>` is guaranteed
///   to be non-negative integer modulo `n`: `0 <= s < n`
///
/// ## Arithmetics
///
/// Supported operations:
/// * Unary: you can [invert](Self::invert) and negate a scalar
/// * Binary: you can add, subtract, and multiply two points
///
/// ### Example
///
///  ```rust
/// # use curv::elliptic::curves::{ScalarZ, Secp256k1};
/// fn expression(
///     a: ScalarZ<Secp256k1>,
///     b: ScalarZ<Secp256k1>,
///     c: ScalarZ<Secp256k1>
/// ) -> ScalarZ<Secp256k1> {
///     a + b * c
/// }
/// ```
#[derive(Serialize, Deserialize)]
#[serde(try_from = "ScalarFormat<E>", into = "ScalarFormat<E>", bound = "")]
pub struct ScalarZ<E: Curve> {
    raw_scalar: E::Scalar,
}

impl<E: Curve> ScalarZ<E> {
    /// Converts a scalar into [`Scalar<E>`](ScalarZ) if it's non-zero, returns None otherwise
    pub fn ensure_nonzero(self) -> Option<Scalar<E>> {
        Scalar::from_raw(self.into_raw()).ok()
    }

    /// Samples a random scalar
    pub fn random() -> Self {
        Self::from_raw(E::Scalar::random())
    }

    /// Constructs zero scalar
    pub fn zero() -> Self {
        Self::from_raw(E::Scalar::zero())
    }

    /// Checks if a scalar is zero
    pub fn is_zero(&self) -> bool {
        self.as_raw().is_zero()
    }

    /// Converts a scalar to [BigInt]
    pub fn to_bigint(&self) -> BigInt {
        self.as_raw().to_bigint()
    }

    /// Constructs a scalar `n % curve_order` from give `n`
    pub fn from_bigint(n: &BigInt) -> Self {
        Self::from_raw(E::Scalar::from_bigint(n))
    }

    /// Returns an order of generator point
    pub fn group_order() -> &'static BigInt {
        E::Scalar::group_order()
    }

    /// Returns inversion `self^-1 mod curve_order`, or None if `self` is zero
    pub fn invert(&self) -> Option<Self> {
        self.as_raw().invert().map(Self::from_raw)
    }

    /// Constructs a `ScalarZ<E>` from low-level [ECScalar] implementor
    ///
    /// Typically, you don't need to use this constructor. See [random](Self::random),
    /// [from_bigint](Self::from_bigint) constructors, and `From<T>`, `TryFrom<T>` traits implemented
    /// for `ScalarZ<E>`.
    ///
    /// [ECScalar]: crate::elliptic::curves::ECScalar
    pub fn from_raw(raw_scalar: E::Scalar) -> Self {
        Self { raw_scalar }
    }

    /// Returns a reference to low-level scalar implementation
    ///
    /// Typically, you don't need to work with `ECScalar` trait directly. `ScalarZ<E>` wraps `ECScalar`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, etc. If you believe that some functionality is missing, please
    /// [open an issue](https://github.com/ZenGo-X/curv).
    pub fn as_raw(&self) -> &E::Scalar {
        &self.raw_scalar
    }

    /// Converts a scalar into inner low-level scalar implementation
    ///
    /// Typically, you don't need to work with `ECScalar` trait directly. `ScalarZ<E>` wraps `ECScalar`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, etc. If you believe that some functionality is missing, please
    /// [open an issue](https://github.com/ZenGo-X/curv).
    pub fn into_raw(self) -> E::Scalar {
        self.raw_scalar
    }
}

impl<E: Curve> Clone for ScalarZ<E> {
    fn clone(&self) -> Self {
        Self::from_raw(self.as_raw().clone())
    }
}

impl<E: Curve> fmt::Debug for ScalarZ<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_raw().fmt(f)
    }
}

impl<E: Curve> PartialEq for ScalarZ<E> {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> PartialEq<Scalar<E>> for ScalarZ<E> {
    fn eq(&self, other: &Scalar<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> From<Scalar<E>> for ScalarZ<E> {
    fn from(scalar: Scalar<E>) -> Self {
        ScalarZ::from_raw(scalar.into_raw())
    }
}

impl<E: Curve> From<u16> for ScalarZ<E> {
    fn from(n: u16) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<u32> for ScalarZ<E> {
    fn from(n: u32) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<u64> for ScalarZ<E> {
    fn from(n: u64) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<i32> for ScalarZ<E> {
    fn from(n: i32) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<&BigInt> for ScalarZ<E> {
    fn from(n: &BigInt) -> Self {
        ScalarZ::from_raw(E::Scalar::from_bigint(n))
    }
}

impl<E: Curve> From<BigInt> for ScalarZ<E> {
    fn from(n: BigInt) -> Self {
        Self::from(&n)
    }
}
