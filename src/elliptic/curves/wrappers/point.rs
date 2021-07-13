use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{
    error::{InvalidPoint, PointFromBytesError, PointFromCoordsError, ZeroPointError},
    format::PointFormat,
    Generator, PointRef, PointZ,
};

/// Elliptic point of [group order](super::Scalar::group_order)
///
/// ## Guarantees
///
/// * On curve
///
///   Any instance of `Point<E>` is guaranteed to belong to curve `E`, i.e. its coordinates must
///   satisfy curve equations
/// * Point order equals to [group order](super::Scalar::group_order)
///
///   I.e. denoting `q = group_order`, following predicate is always true:
///   `qP = O ∧ forall 0 < s < q. sP ≠ O`
///
///   Note that this also means that `Point<E>` cannot be zero (zero point has `order=1`),
///   ie. `forall a b. a: PointZ<E> ∧ b: Point<E> → a + b ≢ a`. It also implies that `Point<E>` is
///   guaranteed to have coordinates (only point at infinity doesn't).
///
/// ## Arithmetics
///
/// You can add, subtract two points, or multiply point at scalar.
///
/// Addition or subtraction of two points might result into zero point, so these operators output
/// [`PointZ<E>`](PointZ) that allowed to be zero.
///
/// ```rust
/// # use curv::elliptic::curves::{PointZ, Point, Scalar, Secp256k1};
/// let p1: Point<Secp256k1> =
///     Point::generator() * Scalar::random(); // Non-zero point
/// let p2: Point<Secp256k1> =
///     Point::generator() * Scalar::random(); // Non-zero point
/// let result: PointZ<Secp256k1> = p1 + p2;   // Addition of two (even non-zero)
///                                            // points might produce zero point
/// let nonzero_result: Option<Point<Secp256k1>> = result.ensure_nonzero();
/// ```
///
/// Multiplying point at non-zero scalar is guaranteed to be non-zero (as point order is known
/// to be equal to group order, and scalar is known to be less then group order):
///
/// ```rust
/// # use curv::elliptic::curves::{PointZ, Point, Scalar, Secp256k1};
/// let s = Scalar::<Secp256k1>::random();   // Non-zero scalar
/// let g = Point::<Secp256k1>::generator(); // Curve generator
/// let result: Point<Secp256k1> = s * g;    // Generator multiplied at non-zero scalar is
///                                          // always a non-zero point
/// ```
#[derive(Serialize, Deserialize)]
#[serde(try_from = "PointFormat<E>", into = "PointFormat<E>", bound = "")]
pub struct Point<E: Curve> {
    raw_point: E::Point,
}

impl<E: Curve> Point<E> {
    /// Curve generator
    ///
    /// Returns a static reference on actual value because in most cases referenced value is fine.
    /// Use [`.to_point()`](Generator::to_point) if you need to take it by value.
    pub fn generator() -> Generator<E> {
        Generator::default()
    }

    /// Curve second generator
    ///
    /// We provide an alternative generator value and prove that it was picked randomly.
    ///
    /// Returns a static reference on actual value because in most cases referenced value is fine.
    /// Use [`.to_point()`](PointRef::to_point) if you need to take it by value.
    pub fn base_point2() -> PointRef<'static, E> {
        let p = E::Point::base_point2();
        PointRef::from_raw(p).expect("base_point2 must have correct order")
    }

    /// Constructs a point from coordinates, returns error if x,y don't satisfy curve equation or
    /// correspond to zero point
    pub fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, PointFromCoordsError> {
        let p = E::Point::from_coords(x, y)
            .map_err(|NotOnCurve { .. }| PointFromCoordsError::PointNotOnCurve)?;
        Self::from_raw(p).map_err(PointFromCoordsError::InvalidPoint)
    }

    /// Tries to parse a point from its (un)compressed form
    ///
    /// Whether it's a compressed or uncompressed form will be deduced from its length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PointFromBytesError> {
        let p = E::Point::deserialize(bytes).map_err(PointFromBytesError::Deserialize)?;
        Self::from_raw(p).map_err(PointFromBytesError::InvalidPoint)
    }

    /// Returns point coordinates (`x` and `y`)
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn coords(&self) -> PointCoords {
        self.as_point().coords()
    }

    /// Returns `x` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn x_coord(&self) -> BigInt {
        self.as_point().x_coord()
    }

    /// Returns `y` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn y_coord(&self) -> BigInt {
        self.as_point().y_coord()
    }

    /// Serializes point into (un)compressed form
    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.as_point().to_bytes(compressed)
    }

    /// Creates [PointRef] that holds a reference on `self`
    pub fn as_point(&self) -> PointRef<E> {
        PointRef::from(self)
    }

    /// Constructs a `Point<E>` from low-level [ECPoint] implementor
    ///
    /// Returns error if point is zero, or its order isn't equal to [group order].
    ///
    /// Typically, you don't need to use this constructor. See [generator](Self::generator),
    /// [base_point2](Self::base_point2), [from_coords](Self::from_coords), [from_bytes](Self::from_bytes)
    /// constructors, and `From<T>` and `TryFrom<T>` traits implemented for `Point<E>`.
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    pub fn from_raw(raw_point: E::Point) -> Result<Self, InvalidPoint> {
        if raw_point.is_zero() {
            Err(InvalidPoint::ZeroPoint)
        } else if !raw_point.check_point_order_equals_group_order() {
            Err(InvalidPoint::MismatchedPointOrder)
        } else {
            Ok(Point { raw_point })
        }
    }

    /// Constructs a `Point<E>` from low-level [ECPoint] implementor
    ///
    /// # Safety
    ///
    /// This function will not perform any checks against the point. You must guarantee that point
    /// order is equal to curve [group order]. To perform this check, you may use
    /// [ECPoint::check_point_order_equals_group_order][check_point_order_equals_group_order]
    /// method.
    ///
    /// Note that it implies that point must not be zero (zero point has `order=1`).
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    /// [check_point_order_equals_group_order]: crate::elliptic::curves::ECPoint::check_point_order_equals_group_order
    pub unsafe fn from_raw_unchecked(point: E::Point) -> Self {
        Point { raw_point: point }
    }

    /// Returns a reference to low-level point implementation
    ///
    /// Typically, you don't need to work with `ECPoint` trait directly. `Point<E>` wraps `ECPoint`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, various getters (like [`.coords()`](Self::coords)). If you believe that some functionality
    /// is missing, please [open an issue](https://github.com/ZenGo-X/curv).
    pub fn as_raw(&self) -> &E::Point {
        &self.raw_point
    }

    /// Converts a point into inner low-level point implementation
    ///
    /// Typically, you don't need to work with `ECPoint` trait directly. `Point<E>` wraps `ECPoint`
    /// and provides convenient utilities around it, it implements arithmetic operators, (de)serialization
    /// traits, various getters (like [`.coords()`](Self::coords)). If you believe that some functionality
    /// is missing, please [open an issue](https://github.com/ZenGo-X/curv).
    pub fn into_raw(self) -> E::Point {
        self.raw_point
    }
}

impl<E: Curve> PartialEq for Point<E> {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().eq(&other.as_raw())
    }
}

impl<E: Curve> PartialEq<PointZ<E>> for Point<E> {
    fn eq(&self, other: &PointZ<E>) -> bool {
        self.as_raw().eq(&other.as_raw())
    }
}

impl<'p, E: Curve> PartialEq<PointRef<'p, E>> for Point<E> {
    fn eq(&self, other: &PointRef<'p, E>) -> bool {
        self.as_raw().eq(&other.as_raw())
    }
}

impl<E: Curve> PartialEq<Generator<E>> for Point<E> {
    fn eq(&self, other: &Generator<E>) -> bool {
        self.as_raw().eq(&other.as_raw())
    }
}

impl<E: Curve> Clone for Point<E> {
    fn clone(&self) -> Self {
        // Safety: `self` is guaranteed to be non-zero
        unsafe { Point::from_raw_unchecked(self.as_raw().clone()) }
    }
}

impl<E: Curve> fmt::Debug for Point<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_raw().fmt(f)
    }
}

impl<E: Curve> TryFrom<PointZ<E>> for Point<E> {
    type Error = ZeroPointError;
    fn try_from(point: PointZ<E>) -> Result<Self, Self::Error> {
        match Self::from_raw(point.into_raw()) {
            Ok(p) => Ok(p),
            Err(InvalidPoint::ZeroPoint) => Err(ZeroPointError(())),
            Err(InvalidPoint::MismatchedPointOrder) => panic!("Point must have correct order"),
        }
    }
}
