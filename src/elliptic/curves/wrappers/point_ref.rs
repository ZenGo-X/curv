use std::fmt;

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{error::InvalidPoint, Generator, Point, PointZ};

/// Reference on elliptic point of [group order](super::Scalar::group_order)
///
/// Holds internally a reference on [`Point<E>`](Point), refer to its documentation to learn
/// more about Point/PointRef guarantees, security notes, and arithmetics.
pub struct PointRef<'p, E: Curve> {
    raw_point: &'p E::Point,
}

impl<E: Curve> PointRef<'static, E> {
    pub fn generator() -> Self {
        Self::from_raw(E::Point::generator()).expect("generator must be non-zero")
    }

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
    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.as_raw()
            .serialize(compressed)
            .expect("non-zero point must always be serializable")
    }

    /// Clones the referenced point
    pub fn to_point(&self) -> Point<E> {
        // Safety: `self` is guaranteed to have order = group_order
        unsafe { Point::from_raw_unchecked(self.as_raw().clone()) }
    }

    pub fn from_raw(raw_point: &'p E::Point) -> Result<Self, InvalidPoint> {
        if raw_point.is_zero() {
            Err(InvalidPoint::ZeroPoint)
        } else if !raw_point.check_point_order_equals_group_order() {
            Err(InvalidPoint::MismatchedPointOrder)
        } else {
            Ok(Self { raw_point })
        }
    }

    pub unsafe fn from_raw_unchecked(raw_point: &'p E::Point) -> Self {
        PointRef { raw_point }
    }

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
