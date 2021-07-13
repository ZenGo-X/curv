use std::fmt;

use serde::Serialize;

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{error::InvalidPoint, format::PointFormat, Generator, Point, PointZ};

/// Reference on elliptic point of [group order](super::Scalar::group_order)
///
/// Holds internally a reference on [`Point<E>`](Point), refer to its documentation to learn
/// more about Point/PointRef guarantees, security notes, and arithmetics.
#[derive(Serialize)]
#[serde(into = "PointFormat<E>", bound = "")]
pub struct PointRef<'p, E: Curve> {
    raw_point: &'p E::Point,
}

impl<E: Curve> PointRef<'static, E> {
    pub fn base_point2() -> Self {
        Self::from_raw(E::Point::base_point2()).expect("base_point2 must be non-zero")
    }
}

impl<'p, E> PointRef<'p, E>
where
    E: Curve,
{
    /// Returns point coordinates (`x` and `y`)
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn coords(&self) -> PointCoords {
        self.as_raw()
            .coords()
            .expect("Point guaranteed to have coordinates")
    }

    /// Returns `x` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn x_coord(&self) -> BigInt {
        self.as_raw()
            .x_coord()
            .expect("Point guaranteed to have coordinates")
    }

    /// Returns `y` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn y_coord(&self) -> BigInt {
        self.as_raw()
            .y_coord()
            .expect("Point guaranteed to have coordinates")
    }

    /// Serializes point into (un)compressed form
    pub fn to_bytes(self, compressed: bool) -> Vec<u8> {
        self.as_raw()
            .serialize(compressed)
            .expect("non-zero point must always be serializable")
    }

    /// Clones the referenced point
    pub fn to_point(self) -> Point<E> {
        // Safety: `self` is guaranteed to have order = group_order
        unsafe { Point::from_raw_unchecked(self.as_raw().clone()) }
    }

    /// Constructs a `PointRef<E>` from reference to low-level [ECPoint] implementor
    ///
    /// Returns error if point is zero, or its order isn't equal to [group order].
    ///
    /// Typically, you don't need to use this constructor. See [generator](Point::generator),
    /// [base_point2](Point::base_point2) constructors, and `From<T>` and `TryFrom<T>` traits
    /// implemented for `Point<E>` and `PointRef<E>`.
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    pub fn from_raw(raw_point: &'p E::Point) -> Result<Self, InvalidPoint> {
        if raw_point.is_zero() {
            Err(InvalidPoint::ZeroPoint)
        } else if !raw_point.check_point_order_equals_group_order() {
            Err(InvalidPoint::MismatchedPointOrder)
        } else {
            Ok(Self { raw_point })
        }
    }

    /// Constructs a `PointRef<E>` from reference to low-level [ECPoint] implementor
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
    pub unsafe fn from_raw_unchecked(raw_point: &'p E::Point) -> Self {
        PointRef { raw_point }
    }

    /// Returns a reference to low-level point implementation
    ///
    /// Typically, you don't need to work with `ECPoint` trait directly. `PointRef<E>` wraps a
    /// reference to `ECPoint` implementation and provides convenient utilities around it: it
    /// implements arithmetic operators, serialization trait, various getters (like
    /// [`.coords()`](Self::coords)). If you believe that some functionality is missing, please
    /// [open an issue](https://github.com/ZenGo-X/curv).
    pub fn as_raw(self) -> &'p E::Point {
        self.raw_point
    }
}

impl<'p, E: Curve> Clone for PointRef<'p, E> {
    fn clone(&self) -> Self {
        // Safety: `self` is guaranteed to be non-zero
        unsafe { Self::from_raw_unchecked(self.as_raw()) }
    }
}

impl<'p, E: Curve> Copy for PointRef<'p, E> {}

impl<'p, E: Curve> fmt::Debug for PointRef<'p, E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_raw().fmt(f)
    }
}

impl<'p, E: Curve> From<&'p Point<E>> for PointRef<'p, E> {
    fn from(point: &'p Point<E>) -> Self {
        // Safety: `point` is guaranteed to be non-zero
        unsafe { PointRef::from_raw_unchecked(point.as_raw()) }
    }
}

impl<'p, E: Curve> PartialEq for PointRef<'p, E> {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<'p, E: Curve> PartialEq<Point<E>> for PointRef<'p, E> {
    fn eq(&self, other: &Point<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<'p, E: Curve> PartialEq<PointZ<E>> for PointRef<'p, E> {
    fn eq(&self, other: &PointZ<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<'p, E: Curve> PartialEq<Generator<E>> for PointRef<'p, E> {
    fn eq(&self, other: &Generator<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}
