use std::marker::PhantomData;

use crate::elliptic::curves::traits::*;

use super::{Point, PointRef};

/// Elliptic curve generator
///
/// Holds internally a static reference on curve generator. Can be used in arithmetic interchangeably
/// as [`PointRef<E>`](PointRef).
///
/// You can convert the generator into `Point<E>` and `PointRef<E>` using
/// [`to_point`](Self::to_point) and [`as_point`](Self::as_point)
/// methods respectively.
///
/// ## Example
///
/// ```rust
/// # use curv::elliptic::curves::{PointZ, Point, Scalar, Secp256k1};
/// let s = Scalar::<Secp256k1>::random();   // Non-zero scalar
/// let g = Point::<Secp256k1>::generator(); // Curve generator
/// let result: Point<Secp256k1> = s * g;    // Generator multiplied at non-zero scalar is
///                                          // always a non-zero point
/// ```
///
/// ## Performance
///
/// Generator multiplication is often more efficient than regular point multiplication, so avoid
/// converting generator into the `Point<E>` as long as it's possible:
///
/// ```rust
/// # use curv::elliptic::curves::{Point, Scalar, Secp256k1, Generator, PointZ};
/// let s: Scalar<Secp256k1> = Scalar::random();
/// // Generator multiplication:
/// let g: Generator<Secp256k1> = Point::generator();
/// let p1: Point<Secp256k1> = g * &s;
/// // Point multiplication:
/// let g: Point<Secp256k1> = g.to_point();
/// let p2: Point<Secp256k1> = g * &s;
/// // Result will be the same, but generator multiplication is usually faster
/// assert_eq!(p1, p2);
/// ```
pub struct Generator<E: Curve> {
    _ph: PhantomData<&'static E::Point>,
}

impl<E: Curve> Default for Generator<E> {
    fn default() -> Self {
        Self { _ph: PhantomData }
    }
}

impl<E: Curve> Generator<E> {
    pub fn as_raw(self) -> &'static E::Point {
        E::Point::generator()
    }

    /// Clones generator point, returns `Point<E>`
    pub fn to_point(self) -> Point<E> {
        // Safety: curve generator must be non-zero point, otherwise nothing will work at all
        unsafe { Point::from_raw_unchecked(self.as_raw().clone()) }
    }

    /// Converts generator into `PointRef<E>`
    pub fn as_point(self) -> PointRef<'static, E> {
        // Safety: curve generator must be non-zero point, otherwise nothing will work at all
        unsafe { PointRef::from_raw_unchecked(self.as_raw()) }
    }
}

impl<E: Curve> Clone for Generator<E> {
    fn clone(&self) -> Self {
        Self { _ph: PhantomData }
    }
}

impl<E: Curve> Copy for Generator<E> {}
