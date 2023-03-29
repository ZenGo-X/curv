use std::{fmt, iter};

use crate::elliptic::curves::traits::{Curve, ECScalar};
use crate::elliptic::curves::wrappers::encoded_scalar::EncodedScalar;
use crate::elliptic::curves::{DeserializationError, ZeroScalarError};
use crate::BigInt;

/// Scalar value in a prime field
///
/// ## Guarantees
///
/// * Modulus group order
///
///   Denoting [group order](Self::group_order) as `n`, any instance `s` of `Scalar<E>` is guaranteed
///   to be non-negative integer modulo `n`: `0 <= s < n`
///
/// ## Arithmetics
///
/// Supported operations:
/// * Unary: you can [invert](Self::invert) and negate a scalar
/// * Binary: you can add, subtract, and multiply two scalars
///
/// ### Example
///
///  ```rust
/// # use curv::elliptic::curves::{Scalar, Secp256k1};
/// fn expression(
///     a: &Scalar<Secp256k1>,
///     b: &Scalar<Secp256k1>,
///     c: &Scalar<Secp256k1>
/// ) -> Scalar<Secp256k1> {
///     a + b * c
/// }
/// ```
#[repr(transparent)]
pub struct Scalar<E: Curve> {
    raw_scalar: E::Scalar,
}

impl<E: Curve> Scalar<E> {
    /// Ensures that `self` is not zero, returns `Err(_)` otherwise
    pub fn ensure_nonzero(&self) -> Result<(), ZeroScalarError> {
        if self.is_zero() {
            Err(ZeroScalarError::new())
        } else {
            Ok(())
        }
    }

    /// Samples a random nonzero scalar
    pub fn random() -> Self {
        loop {
            let s = E::Scalar::random();
            if !s.is_zero() {
                break Scalar::from_raw(s);
            }
        }
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

    /// Constructs a scalar `n % curve_order` from given `n`
    pub fn from_bigint(n: &BigInt) -> Self {
        Self::from_raw(E::Scalar::from_bigint(n))
    }

    /// Serializes a scalar to bytes
    pub fn to_bytes(&self) -> EncodedScalar<E> {
        EncodedScalar::from(self)
    }

    /// Constructs a scalar from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        ECScalar::deserialize(bytes).map(Self::from_raw)
    }

    /// Returns an order of generator point
    pub fn group_order() -> &'static BigInt {
        E::Scalar::group_order()
    }

    /// Returns inversion `self^-1 mod group_order`, or None if `self` is zero
    pub fn invert(&self) -> Option<Self> {
        self.as_raw().invert().map(Self::from_raw)
    }

    /// Constructs a `Scalar<E>` from low-level [ECScalar] implementor
    ///
    /// Typically, you don't need to use this constructor. See [random](Self::random),
    /// [from_bigint](Self::from_bigint) constructors, and `From<T>`, `TryFrom<T>` traits implemented
    /// for `Scalar<E>`.
    ///
    /// [ECScalar]: crate::elliptic::curves::ECScalar
    pub fn from_raw(raw_scalar: E::Scalar) -> Self {
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
        Self::from_raw(self.as_raw().clone())
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

impl<E: Curve> Eq for Scalar<E> {}

impl<E: Curve> From<u16> for Scalar<E> {
    fn from(n: u16) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<u32> for Scalar<E> {
    fn from(n: u32) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<u64> for Scalar<E> {
    fn from(n: u64) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<i32> for Scalar<E> {
    fn from(n: i32) -> Self {
        Self::from(&BigInt::from(n))
    }
}

impl<E: Curve> From<&BigInt> for Scalar<E> {
    fn from(n: &BigInt) -> Self {
        Scalar::from_raw(E::Scalar::from_bigint(n))
    }
}

impl<E: Curve> From<BigInt> for Scalar<E> {
    fn from(n: BigInt) -> Self {
        Self::from(&n)
    }
}

impl<E: Curve> iter::Sum for Scalar<E> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Scalar::zero(), |acc, s| acc + s)
    }
}

impl<'s, E: Curve> iter::Sum<&'s Scalar<E>> for Scalar<E> {
    fn sum<I: Iterator<Item = &'s Scalar<E>>>(iter: I) -> Self {
        iter.fold(Scalar::zero(), |acc, s| acc + s)
    }
}

impl<E: Curve> iter::Product for Scalar<E> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Scalar::from(1), |acc, s| acc * s)
    }
}

impl<'s, E: Curve> iter::Product<&'s Scalar<E>> for Scalar<E> {
    fn product<I: Iterator<Item = &'s Scalar<E>>>(iter: I) -> Self {
        iter.fold(Scalar::from(1), |acc, s| acc * s)
    }
}
