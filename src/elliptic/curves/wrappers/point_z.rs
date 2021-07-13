use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{
    error::{MismatchedPointOrder, PointZDeserializationError, PointZFromCoordsError},
    format::PointFormat,
    Generator, Point, PointRef,
};

/// Either an elliptic point of a [group order](super::Scalar::group_order), or a zero point
///
/// ## Security
///
/// Mistakenly used zero point might break security of cryptographic algorithm. It's preferred to
/// use [`Point<E>`](Point) that's guaranteed to be non-zero. Use [ensure_nonzero](PointZ::ensure_nonzero)
/// to convert `PointZ` into `Point`.
///
/// ## Guarantees
///
/// * On curve
///
///   Any instance of `PointZ<E>` is guaranteed to belong to curve `E`, i.e. its coordinates must
///   satisfy curve equations
/// * Point order equals to [group order](super::Scalar::group_order) (unless it's zero point)
///
///   I.e. denoting `q = group_order`, following predicate is always true:
///   `P = O ∨ qP = O ∧ forall 0 < s < q. sP ≠ O`
///
/// ## Arithmetics
///
/// You can add, subtract two points, or multiply point at scalar:
///
/// ```rust
/// # use curv::elliptic::curves::{PointZ, Scalar, Secp256k1};
/// fn expression(
///     a: PointZ<Secp256k1>,
///     b: PointZ<Secp256k1>,
///     c: Scalar<Secp256k1>,
/// ) -> PointZ<Secp256k1> {
///     a + b * c
/// }
/// ```
#[derive(Serialize, Deserialize)]
#[serde(try_from = "PointFormat<E>", into = "PointFormat<E>", bound = "")]
pub struct PointZ<E: Curve> {
    raw_point: E::Point,
}

impl<E: Curve> PointZ<E> {
    /// Checks if `self` is not zero and converts it into [`Point<E>`](Point). Returns `None` if
    /// it's zero.
    pub fn ensure_nonzero(self) -> Option<Point<E>> {
        Point::try_from(self).ok()
    }

    /// Constructs zero point
    ///
    /// Zero point (or curve neutral element) is usually denoted as `O`. Its property: `forall A. A + O = A`.
    ///
    /// Weierstrass and Montgomery curves employ special "point at infinity" that represent a neutral
    /// element, such points don't have coordinates (i.e. [from_coords], [x_coord], [y_coord] return
    /// `None`). Edwards curves' neutral element has coordinates.
    ///
    /// [from_coords]: Self::from_coords
    /// [x_coord]: Self::x_coord
    /// [y_coord]: Self::y_coord
    pub fn zero() -> Self {
        // Safety: `self` can be constructed to hold a zero point
        unsafe { Self::from_raw_unchecked(E::Point::zero()) }
    }

    /// Checks whether point is zero
    pub fn is_zero(&self) -> bool {
        self.as_raw().is_zero()
    }

    /// Returns point coordinates
    ///
    /// Point might not have coordinates (specifically, "point at infinity" doesn't), in this case
    /// `None` is returned
    pub fn coords(&self) -> Option<PointCoords> {
        self.as_raw().coords()
    }

    /// Returns point x coordinate
    ///
    /// See [coords](Self::coords) method that retrieves both x and y at once.
    pub fn x_coord(&self) -> Option<BigInt> {
        self.as_raw().x_coord()
    }

    /// Returns point y coordinate
    ///
    /// See [coords](Self::coords) method that retrieves both x and y at once.
    pub fn y_coord(&self) -> Option<BigInt> {
        self.as_raw().y_coord()
    }

    /// Constructs a point from its coordinates, returns error if coordinates don't satisfy
    /// curve equation or if point has invalid order
    pub fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, PointZFromCoordsError> {
        let raw_point = E::Point::from_coords(x, y)
            .map_err(|_: NotOnCurve| PointZFromCoordsError::NotOnCurve)?;
        Self::from_raw(raw_point).map_err(PointZFromCoordsError::InvalidPoint)
    }

    /// Tries to parse a point in (un)compressed form
    ///
    /// Whether it's in compressed or uncompressed form will be deduced from its length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PointZDeserializationError> {
        let p = E::Point::deserialize(bytes)
            .map_err(|_: DeserializationError| PointZDeserializationError::DeserializationError)?;
        Self::from_raw(p).map_err(PointZDeserializationError::InvalidPoint)
    }

    /// Serializes a point in (un)compressed form
    ///
    /// Returns `None` if it's point at infinity
    pub fn to_bytes(&self, compressed: bool) -> Option<Vec<u8>> {
        self.as_raw().serialize(compressed)
    }

    /// Constructs a `Point<E>` from low-level [ECPoint] implementor
    ///
    /// Returns error if point is zero, or its order isn't equal to [group order].
    ///
    /// Typically, you don't need to use this constructor. See [generator](Point::generator),
    /// [base_point2](Point::base_point2), [from_coords](Self::from_coords), [from_bytes](Self::from_bytes)
    /// constructors, and `From<T>` and `TryFrom<T>` traits implemented for `PointZ<E>`.
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    pub fn from_raw(raw_point: E::Point) -> Result<Self, MismatchedPointOrder> {
        if raw_point.is_zero() || raw_point.check_point_order_equals_group_order() {
            Ok(Self { raw_point })
        } else {
            Err(MismatchedPointOrder(()))
        }
    }

    /// Constructs a `PointZ<E>` from low-level [ECPoint] implementor
    ///
    /// # Safety
    ///
    /// This function will not perform any checks against the point. You must guarantee that either
    /// point order is equal to curve [group order] or it's a zero point. To perform this check, you
    /// may use [ECPoint::check_point_order_equals_group_order][check_point_order_equals_group_order]
    /// and [ECPoint::is_zero][is_zero] methods.
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    /// [check_point_order_equals_group_order]: crate::elliptic::curves::ECPoint::check_point_order_equals_group_order
    /// [is_zero]: crate::elliptic::curves::ECPoint::is_zero
    pub unsafe fn from_raw_unchecked(raw_point: E::Point) -> Self {
        Self { raw_point }
    }

    /// Returns a reference to low-level point implementation
    ///
    /// Typically, you don't need to work with `ECPoint` trait directly. `PointZ<E>` wrapper
    /// provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, various getters (like [`.coords()`](Self::coords). If you believe that some functionality
    /// is missing, please [open an issue](https://github.com/ZenGo-X/curv).
    pub fn as_raw(&self) -> &E::Point {
        &self.raw_point
    }

    /// Converts a point into inner low-level point implementation
    ///
    /// Typically, you don't need to work with `ECPoint` trait directly. `PointZ<E>` wraps `ECPoint`
    /// and provides convenient utilities around it: it implements arithmetic operators, (de)serialization
    /// traits, various getters (like [`.coords()`](Self::coords)). If you believe that some functionality
    /// is missing, please [open an issue](https://github.com/ZenGo-X/curv).
    pub fn into_raw(self) -> E::Point {
        self.raw_point
    }
}

impl<E: Curve> PartialEq for PointZ<E> {
    fn eq(&self, other: &Self) -> bool {
        self.raw_point.eq(&other.raw_point)
    }
}

impl<E: Curve> PartialEq<Point<E>> for PointZ<E> {
    fn eq(&self, other: &Point<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<'p, E: Curve> PartialEq<PointRef<'p, E>> for PointZ<E> {
    fn eq(&self, other: &PointRef<'p, E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> PartialEq<Generator<E>> for PointZ<E> {
    fn eq(&self, other: &Generator<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<E: Curve> Clone for PointZ<E> {
    fn clone(&self) -> Self {
        // Safety: self is guaranteed to have correct order
        unsafe { PointZ::from_raw_unchecked(self.as_raw().clone()) }
    }
}

impl<E: Curve> fmt::Debug for PointZ<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.raw_point.fmt(f)
    }
}

impl<E: Curve> From<Point<E>> for PointZ<E> {
    fn from(p: Point<E>) -> Self {
        // Safety: `Point` is guaranteed to have correct order
        unsafe { PointZ::from_raw_unchecked(p.into_raw()) }
    }
}
