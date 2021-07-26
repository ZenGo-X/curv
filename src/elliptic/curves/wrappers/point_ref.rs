use std::fmt;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::{error::MismatchedPointOrder, EncodedPoint, Generator, Point};

/// Holds a reference to elliptic point of [group order](super::Scalar::group_order) or to zero point
///
/// Holds internally a reference to [`Point<E>`](Point), refer to its documentation to learn
/// more about Point/PointRef guarantees, security notes, and arithmetics.
pub struct PointRef<'p, E: Curve> {
    raw_point: &'p E::Point,
}

impl<E: Curve> PointRef<'static, E> {
    /// Curve second generator
    ///
    /// We provide an alternative generator value and prove that it was picked randomly.
    pub fn base_point2() -> Self {
        Self::from_raw(E::Point::base_point2()).expect("base_point2 must be of group_order")
    }
}

impl<'p, E> PointRef<'p, E>
where
    E: Curve,
{
    /// Returns point coordinates (`x` and `y`)
    ///
    /// Point might not have coordinates (specifically, "point at infinity" doesn't), in this case
    /// `None` is returned. Also, some curve libraries do not expose point coordinates (eg. see
    /// [Ristretto] curve implementation notes).
    ///
    /// [Ristretto]: crate::elliptic::curves::Ristretto
    pub fn coords(&self) -> Option<PointCoords> {
        self.as_raw().coords()
    }

    /// Returns `x` coordinate of point
    ///
    /// See [coords](Self::coords) method that retrieves both x and y at once.
    pub fn x_coord(&self) -> Option<BigInt> {
        self.as_raw().x_coord()
    }

    /// Returns `y` coordinate of point
    ///
    /// See [coords](Self::coords) method that retrieves both x and y at once.
    pub fn y_coord(&self) -> Option<BigInt> {
        self.as_raw().y_coord()
    }

    /// Serializes point into (un)compressed form
    pub fn to_bytes(self, compressed: bool) -> EncodedPoint<E> {
        if compressed {
            EncodedPoint::Compressed(self.as_raw().serialize_compressed())
        } else {
            EncodedPoint::Uncompressed(self.as_raw().serialize_uncompressed())
        }
    }

    /// Clones the referenced point
    pub fn to_point(self) -> Point<E> {
        // Safety: `self` holds the same guarantees as `Point` requires to meet
        unsafe { Point::from_raw_unchecked(self.as_raw().clone()) }
    }

    /// Constructs a `PointRef<E>` from reference to low-level [ECPoint] implementor
    ///
    /// Returns error if point is not valid. Valid point is either a zero point, or a point of
    /// [group order].
    ///
    /// Typically, you don't need to use this constructor. See [generator](Point::generator),
    /// [base_point2](Point::base_point2) constructors, and `From<T>` and `TryFrom<T>` traits
    /// implemented for `Point<E>` and `PointRef<E>`.
    ///
    /// [ECPoint]: crate::elliptic::curves::ECPoint
    /// [group order]: crate::elliptic::curves::ECScalar::group_order
    pub fn from_raw(raw_point: &'p E::Point) -> Result<Self, MismatchedPointOrder> {
        if raw_point.is_zero() || raw_point.check_point_order_equals_group_order() {
            Ok(Self { raw_point })
        } else {
            Err(MismatchedPointOrder::new())
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
        // Safety: `self` is guaranteed to be nonzero
        unsafe { Self::from_raw_unchecked(self.as_raw()) }
    }
}

impl<'p, E: Curve> Copy for PointRef<'p, E> {}

impl<'p, E: Curve> fmt::Debug for PointRef<'p, E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_raw().fmt(f)
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

impl<'p, E: Curve> PartialEq<Generator<E>> for PointRef<'p, E> {
    fn eq(&self, other: &Generator<E>) -> bool {
        self.as_raw().eq(other.as_raw())
    }
}

impl<'p, E: Curve> From<&'p Point<E>> for PointRef<'p, E> {
    fn from(point: &'p Point<E>) -> Self {
        // Safety: `Point` holds the same guarantees as `PointRef`
        unsafe { PointRef::from_raw_unchecked(point.as_raw()) }
    }
}

impl<E: Curve> From<Generator<E>> for PointRef<'static, E> {
    fn from(g: Generator<E>) -> Self {
        // Safety: generator must be of group_order
        unsafe { PointRef::from_raw_unchecked(g.as_raw()) }
    }
}

impl<'p, E: Curve> Serialize for PointRef<'p, E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde_bytes::Bytes;

        let mut s = serializer.serialize_struct("Point", 2)?;
        s.serialize_field("curve", E::CURVE_NAME)?;
        s.serialize_field(
            "point",
            // Serializes bytes efficiently
            Bytes::new(&self.to_bytes(true)),
        )?;
        s.end()
    }
}
