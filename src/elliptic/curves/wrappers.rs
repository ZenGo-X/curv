use std::borrow::Cow;
use std::convert::TryFrom;
use std::{fmt, iter, ops};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::traits::*;
use crate::arithmetic::{BigInt, Converter};

/// Elliptic point that **might be zero**
///
/// ## Security
///
/// Mistakenly used zero point might break security of cryptographic algorithm. It's preferred to
/// use [`Point<E>`](Point) that's guaranteed to be non-zero. Use [ensure_nonzero](PointZ::ensure_nonzero)
/// to convert `PointZ` into `Point`.
///
/// ## Guarantees
///
/// * Belongs to curve
///
///   Any instance of `PointZ<E>` is guaranteed to belong to curve `E`, i.e. its coordinates must
///   satisfy curve equations
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
pub struct PointZ<E: Curve>(E::Point);

impl<E: Curve> PointZ<E> {
    /// Checks if `self` is not zero and converts it into [`Point<E>`](Point). Returns `None` if
    /// it's zero.
    pub fn ensure_nonzero(self) -> Option<Point<E>> {
        Point::try_from(self).ok()
    }

    pub fn zero() -> Self {
        Self::from_raw(E::Point::zero())
    }

    pub fn iz_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn coords(&self) -> Option<PointCoords> {
        self.0.coords()
    }

    pub fn x_coord(&self) -> Option<BigInt> {
        self.0.x_coord()
    }

    pub fn y_coord(&self) -> Option<BigInt> {
        self.0.y_coord()
    }

    fn from_raw(point: E::Point) -> Self {
        Self(point)
    }
}

impl<E: Curve> PartialEq for PointZ<E> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<E: Curve> Clone for PointZ<E> {
    fn clone(&self) -> Self {
        PointZ(self.0.clone())
    }
}

impl<E: Curve> fmt::Debug for PointZ<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Elliptic point that _guaranteed_ to be non zero
///
/// ## Security
/// Non-zero points are preferred to be used in cryptographic algorithms. Lack of checking whether
/// computation on elliptic points results into zero point might lead to vulnerabilities. Using
/// `Point<E>` ensures you and reviewers that check on point not being zero was made.
///
/// ## Guarantees
///
/// * Belongs to curve
///
///   Any instance of `Point<E>` is guaranteed to belong to curve `E`, i.e. its coordinates must
///   satisfy curve equations
/// * Not a neutral element
///
///   Any instance of `Point<E>` is restricted not to be zero (neutral element), i.e. for any
///   `a: PointZ<E> ∧ b: Point<E> → a + b ≢ a`.
///
///   Weierstrass and Montgomery curves represent zero point
///   using special "point at infinity", whereas Edwards curves zero point is a regular point that
///   has coordinates. `Point<E>` cannot be instantiated with neither of these points.
///
///   Note also that `Point<E>` is guaranteed to have coordinates (only point at infinity doesn't).
///
/// ## Arithmetics
///
/// You can add, subtract two points, or multiply point at scalar.
///
/// Any arithmetic operation on non-zero point might result into zero point, so addition, subtraction,
/// and multiplication operations output [PointZ]. Use [ensure_nonzero](PointZ::ensure_nonzero) method
/// to ensure that computation doesn't produce zero-point:
///
/// ```rust
/// # use curv::elliptic::curves::{PointZ, Point, Scalar, Secp256k1};
/// let s = Scalar::<Secp256k1>::random();   // Non-zero scalar
/// let g = Point::<Secp256k1>::generator(); // Non-zero point (curve generator)
/// let result: PointZ<Secp256k1> = s * g;   // Multiplication of two non-zero points
///                                          // might produce zero-point
/// let nonzero_result: Option<Point<Secp256k1>> = result.ensure_nonzero();
/// ```
///
/// When evaluating complex expressions, you typically need to ensure that none of intermediate
/// results are zero-points:
///
/// ```rust
/// # use curv::elliptic::curves::{Curve, Point, Scalar};
/// fn expression<E: Curve>(a: Point<E>, b: Point<E>, c: Scalar<E>) -> Option<Point<E>> {
///     (a + (b * c).ensure_nonzero()?).ensure_nonzero()
/// }
/// ```
pub struct Point<E: Curve>(E::Point);

impl<E: Curve> Point<E> {
    fn from_raw(point: E::Point) -> Result<Self, ZeroPointError> {
        if point.is_zero() {
            Err(ZeroPointError(()))
        } else {
            Ok(Self(point))
        }
    }

    /// Curve generator
    ///
    /// Returns a static reference on actual value because in most cases referenced value is fine.
    /// Use [`.to_point_owned()`](PointRef::to_point_owned) if you need to take it by value.
    pub fn generator() -> PointRef<'static, E> {
        let p = E::Point::generator();
        PointRef::from_raw(p).expect("generator must be non-zero")
    }

    /// Curve second generator
    ///
    /// We provide an alternative generator value and prove that it was picked randomly.
    ///
    /// Returns a static reference on actual value because in most cases referenced value is fine.
    /// Use [`.to_point_owned()`](PointRef::to_point_owned) if you need to take it by value.
    pub fn base_point2() -> PointRef<'static, E> {
        let p = E::Point::base_point2();
        PointRef::from_raw(p).expect("base_point2 must be non-zero")
    }

    /// Constructs a point from coordinates, returns error if x,y don't satisfy curve equation or
    /// correspond to zero point
    pub fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, PointFromCoordsError> {
        let p = E::Point::from_coords(x, y)
            .map_err(|NotOnCurve { .. }| PointFromCoordsError::PointNotOnCurve)?;
        Self::from_raw(p).map_err(|ZeroPointError(())| PointFromCoordsError::ZeroPoint)
    }

    /// Tries to parse a point from its (un)compressed form
    ///
    /// Whether it's a compressed or uncompressed form will be deduced from its length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PointFromBytesError> {
        let p = E::Point::deserialize(bytes).map_err(PointFromBytesError::Deserialize)?;
        Self::from_raw(p).map_err(|ZeroPointError(())| PointFromBytesError::ZeroPoint)
    }

    /// Returns point coordinates (`x` and `y`)
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn coords(&self) -> PointCoords {
        self.as_point_ref().coords()
    }

    /// Returns `x` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn x_coord(&self) -> BigInt {
        self.as_point_ref().x_coord()
    }

    /// Returns `y` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn y_coord(&self) -> BigInt {
        self.as_point_ref().y_coord()
    }

    /// Adds two points, returns the result, or `None` if resulting point is zero
    pub fn add_checked(&self, point: PointRef<E>) -> Option<Self> {
        self.as_point_ref().add_checked(point)
    }

    /// Substrates two points, returns the result, or `None` if resulting point is zero
    pub fn sub_checked(&self, point: PointRef<E>) -> Option<Self> {
        self.as_point_ref().sub_checked(point)
    }

    /// Multiplies a point at scalar, returns the result, or `None` if resulting point is zero
    pub fn mul_checked_z(&self, scalar: &ScalarZ<E>) -> Option<Self> {
        self.as_point_ref().mul_checked_z(scalar)
    }

    /// Multiplies a point at nonzero scalar, returns the result, or `None` if resulting point is zero
    pub fn mul_checked(&self, scalar: &Scalar<E>) -> Option<Self> {
        self.as_point_ref().mul_checked(scalar)
    }

    /// Serializes point into (un)compressed form
    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.as_point_ref().to_bytes(compressed)
    }

    /// Creates [PointRef] that holds a reference on `self`
    pub fn as_point_ref(&self) -> PointRef<E> {
        PointRef(&self.0)
    }
}

impl<E: Curve> Clone for Point<E> {
    fn clone(&self) -> Self {
        Point(self.0.clone())
    }
}

impl<E: Curve> fmt::Debug for Point<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: Curve> TryFrom<PointZ<E>> for Point<E> {
    type Error = ZeroPointError;
    fn try_from(point: PointZ<E>) -> Result<Self, Self::Error> {
        Self::from_raw(point.0)
    }
}

/// Reference on elliptic point, _guaranteed_ to be non-zero
///
/// Holds internally a reference on [`Point<E>`](Point), refer to its documentation to learn
/// more about Point/PointRef guarantees, security notes, and arithmetics.
pub struct PointRef<'p, E: Curve>(&'p E::Point);

impl<'p, E: Curve> Clone for PointRef<'p, E> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<'p, E: Curve> Copy for PointRef<'p, E> {}

impl<'p, E: Curve> fmt::Debug for PointRef<'p, E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
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
    fn from_raw(point: &'p E::Point) -> Option<Self> {
        if point.is_zero() {
            None
        } else {
            Some(Self(point))
        }
    }

    /// Returns point coordinates (`x` and `y`)
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn coords(&self) -> PointCoords {
        self.0
            .coords()
            .expect("Point guaranteed to have coordinates")
    }

    /// Returns `x` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn x_coord(&self) -> BigInt {
        self.0
            .x_coord()
            .expect("Point guaranteed to have coordinates")
    }

    /// Returns `y` coordinate of point
    ///
    /// Method never fails as Point is guaranteed to have coordinates
    pub fn y_coord(&self) -> BigInt {
        self.0
            .y_coord()
            .expect("Point guaranteed to have coordinates")
    }

    /// Adds two points, returns the result, or `None` if resulting point is at infinity
    pub fn add_checked(&self, point: Self) -> Option<Point<E>> {
        let new_point = self.0.add_point(&point.0);
        if new_point.is_zero() {
            None
        } else {
            Some(Point(new_point))
        }
    }

    /// Substrates two points, returns the result, or `None` if resulting point is at infinity
    pub fn sub_checked(&self, point: Self) -> Option<Point<E>> {
        let new_point = self.0.sub_point(&point.0);
        if new_point.is_zero() {
            None
        } else {
            Some(Point(new_point))
        }
    }

    /// Multiplies a point at scalar, returns the result, or `None` if resulting point is at infinity
    pub fn mul_checked_z(&self, scalar: &ScalarZ<E>) -> Option<Point<E>> {
        let new_point = self.0.scalar_mul(&scalar.0);
        if new_point.is_zero() {
            None
        } else {
            Some(Point(new_point))
        }
    }

    /// Multiplies a point at nonzero scalar, returns the result, or `None` if resulting point is at infinity
    pub fn mul_checked(&self, scalar: &Scalar<E>) -> Option<Point<E>> {
        let new_point = self.0.scalar_mul(&scalar.0);
        if new_point.is_zero() {
            None
        } else {
            Some(Point(new_point))
        }
    }

    /// Serializes point into (un)compressed form
    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.0
            .serialize(compressed)
            .expect("non-zero point must always be serializable")
    }

    /// Clones the referenced point
    pub fn to_point_owned(&self) -> Point<E> {
        Point(self.0.clone())
    }
}

/// Converting PointZ to Point error
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZeroPointError(());

impl fmt::Display for ZeroPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nonzero check failed: point is zero")
    }
}

impl std::error::Error for ZeroPointError {}

/// Constructing Point from its coordinates error
#[derive(Debug, Error)]
pub enum PointFromCoordsError {
    #[error("x,y correspond to zero point")]
    ZeroPoint,
    #[error("point is not on the curve")]
    PointNotOnCurve,
}

/// Constructing Point from its (un)compressed representation error
#[derive(Debug, Error)]
pub enum PointFromBytesError {
    #[error("deserialized point corresponds to zero point")]
    ZeroPoint,
    #[error("{0}")]
    Deserialize(#[source] DeserializationError),
}

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
/// * Belongs to the curve prime field
///
///   Denoting curve modulus as `q`, any instance `s` of `ScalarZ<E>` is guaranteed to be non-negative
///   integer modulo `q`: `0 <= s < q`
///
/// ## Arithmetics
///
/// Supported operations:
/// * Unary: you can [invert](Self::invert) and negate a scalar by modulo of prime field
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
#[serde(try_from = "ScalarFormat<E>", into = "ScalarFormat<E>")]
pub struct ScalarZ<E: Curve>(E::Scalar);

impl<E: Curve> ScalarZ<E> {
    pub fn ensure_nonzero(self) -> Option<Scalar<E>> {
        Scalar::from_raw(self.0)
    }

    fn from_raw(scalar: E::Scalar) -> Self {
        Self(scalar)
    }

    pub fn random() -> Self {
        Self::from_raw(E::Scalar::random())
    }

    pub fn zero() -> Self {
        Self::from_raw(E::Scalar::zero())
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn to_bigint(&self) -> BigInt {
        self.0.to_bigint()
    }

    pub fn from_bigint(n: &BigInt) -> Self {
        Self::from_raw(E::Scalar::from_bigint(n))
    }

    pub fn invert(&self) -> Option<Self> {
        self.0.invert().map(Self::from_raw)
    }
}

impl<E: Curve> Clone for ScalarZ<E> {
    fn clone(&self) -> Self {
        Self::from_raw(self.0.clone())
    }
}

impl<E: Curve> fmt::Debug for ScalarZ<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: Curve> PartialEq for ScalarZ<E> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<E: Curve> PartialEq<Scalar<E>> for ScalarZ<E> {
    fn eq(&self, other: &Scalar<E>) -> bool {
        self.0.eq(&other.0)
    }
}

impl<E: Curve> From<Scalar<E>> for ScalarZ<E> {
    fn from(scalar: Scalar<E>) -> Self {
        ScalarZ::from_raw(scalar.0)
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
///   Denoting curve modulus as `q`, any instance `s` of `Scalar<E>` is guaranteed to be less than `q`:
///   `s < q`
/// * Not a zero
///
///   Any instance `s` of `Scalar<E>` is guaranteed to be more than zero: `s > 0`
///
/// Combining two rules above, any instance `s` of `Scalar<E>` is guaranteed to be: `0 < s < q`.
///
/// ## Arithmetic
///
/// Supported operations:
/// * Unary: you can [invert](Self::invert) and negate a scalar by modulo of prime field
/// * Binary: you can add, subtract, and multiply two points
///
/// Addition, subtraction, or multiplication of two (even non-zero) scalars might result into zero
/// scalar, so these operations output [ScalarZ]. Use [ensure_nonzero](ScalarZ::ensure_nonzero) method
/// to ensure that computation doesn't produce zero scalar;
///
/// ```rust
/// # use curv::elliptic::curves::{ScalarZ, Scalar, Secp256k1};
/// let a = Scalar::<Secp256k1>::random();
/// let b = Scalar::<Secp256k1>::random();
/// let result: ScalarZ<Secp256k1> = a * b;
/// let non_zero_result: Option<Scalar<Secp256k1>> = result.ensure_nonzero();
/// ```
///
/// When evaluating complex expressions, you typically need to ensure that none of intermediate
/// results are zero scalars:
/// ```rust
/// # use curv::elliptic::curves::{Scalar, Secp256k1};
/// fn expression(a: Scalar<Secp256k1>, b: Scalar<Secp256k1>, c: Scalar<Secp256k1>) -> Option<Scalar<Secp256k1>> {
///     (a + (b * c).ensure_nonzero()?).ensure_nonzero()
/// }
/// ```
#[derive(Serialize, Deserialize)]
#[serde(try_from = "ScalarFormat<E>", into = "ScalarFormat<E>")]
pub struct Scalar<E: Curve>(E::Scalar);

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
        self.0
            .invert()
            .map(Self)
            .expect("non-zero scalar must have corresponding inversion")
    }

    /// Adds two scalars, returns the result by modulo `q`, or `None` if resulting scalar is zero
    pub fn add_checked(&self, scalar: &Scalar<E>) -> Option<Self> {
        let scalar = self.0.add(&scalar.0);
        Self::from_raw(scalar)
    }

    /// Subtracts two scalars, returns the result by modulo `q`, or `None` if resulting scalar is zero
    pub fn sub_checked(&self, scalar: &Scalar<E>) -> Option<Self> {
        let scalar = self.0.sub(&scalar.0);
        Self::from_raw(scalar)
    }

    /// Multiplies two scalars, returns the result by modulo `q`, or `None` if resulting scalar is zero
    pub fn mul_checked(&self, scalar: &Scalar<E>) -> Option<Self> {
        let scalar = self.0.mul(&scalar.0);
        Self::from_raw(scalar)
    }

    fn from_raw(scalar: E::Scalar) -> Option<Self> {
        if scalar.is_zero() {
            None
        } else {
            Some(Self(scalar))
        }
    }
}

impl<E: Curve> Clone for Scalar<E> {
    fn clone(&self) -> Self {
        Scalar(self.0.clone())
    }
}

impl<E: Curve> fmt::Debug for Scalar<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: Curve> PartialEq for Scalar<E> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<E: Curve> PartialEq<ScalarZ<E>> for Scalar<E> {
    fn eq(&self, other: &ScalarZ<E>) -> bool {
        self.0.eq(&other.0)
    }
}

macro_rules! matrix {
    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:ident,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(r_<$($l:lifetime),*> $lhs_ref:ty, $rhs:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs> for $lhs_ref {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs) -> Self::Output {
                let p = self.0.$point_fn(&rhs.0);
                $output_new(p)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:ident,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(_r<$($l:lifetime),*> $lhs:ty, $rhs_ref:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs_ref> for $lhs {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs_ref) -> Self::Output {
                let p = rhs.0.$point_fn(&self.0);
                $output_new(p)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:ident,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(o_<$($l:lifetime),*> $lhs_owned:ty, $rhs:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs> for $lhs_owned {
            type Output = $output;
            fn $trait_fn(mut self, rhs: $rhs) -> Self::Output {
                self.0.$point_assign_fn(&rhs.0);
                $output_new(self.0)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:ident,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(_o<$($l:lifetime),*> $lhs:ty, $rhs_owned:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs_owned> for $lhs {
            type Output = $output;
            fn $trait_fn(self, mut rhs: $rhs_owned) -> Self::Output {
                rhs.0.$point_assign_fn(&self.0);
                $output_new(rhs.0)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:ident,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {}
    ) => {
        // happy termination
    };
}

matrix! {
    trait = Add,
    trait_fn = add,
    output = PointZ<E>,
    output_new = PointZ,
    point_fn = add_point,
    point_assign_fn = add_point_assign,
    pairs = {
        (o_<> Point<E>, &Point<E>), (o_<> Point<E>, &PointZ<E>),
        (r_<> &Point<E>, &Point<E>), (r_<> &Point<E>, &PointZ<E>),
        (o_<> PointZ<E>, &Point<E>), (o_<> PointZ<E>, &PointZ<E>),
        (r_<> &PointZ<E>, &Point<E>), (r_<> &PointZ<E>, &PointZ<E>),
        (o_<> Point<E>, Point<E>), (o_<> PointZ<E>, PointZ<E>),
        (o_<> Point<E>, PointZ<E>), (o_<> PointZ<E>, Point<E>),
        (_o<> &Point<E>, Point<E>), (_o<> &Point<E>, PointZ<E>),
        (_o<> &PointZ<E>, Point<E>), (_o<> &PointZ<E>, PointZ<E>),

        // The same as above, but replacing &Point<E> with PointRef<E>
        (o_<'r> Point<E>, PointRef<'r, E>),
        (r_<'a, 'b> PointRef<'a, E>, PointRef<'b, E>), (r_<'r> PointRef<'r, E>, &PointZ<E>),
        (o_<'r> PointZ<E>, PointRef<'r, E>),
        (r_<'r> &PointZ<E>, PointRef<'r, E>),
        (_o<'r> PointRef<'r, E>, Point<E>), (_o<'r> PointRef<'r, E>, PointZ<E>),

        // And define trait between &Point<E> and PointRef<E>
        (r_<'r> &Point<E>, PointRef<'r, E>), (r_<'r> PointRef<'r, E>, &Point<E>),
    }
}

matrix! {
    trait = Sub,
    trait_fn = sub,
    output = PointZ<E>,
    output_new = PointZ,
    point_fn = sub_point,
    point_assign_fn = sub_point_assign,
    pairs = {
        (o_<> Point<E>, &Point<E>), (o_<> Point<E>, &PointZ<E>),
        (r_<> &Point<E>, &Point<E>), (r_<> &Point<E>, &PointZ<E>),
        (o_<> PointZ<E>, &Point<E>), (o_<> PointZ<E>, &PointZ<E>),
        (r_<> &PointZ<E>, &Point<E>), (r_<> &PointZ<E>, &PointZ<E>),
        (o_<> Point<E>, Point<E>), (o_<> PointZ<E>, PointZ<E>),
        (o_<> Point<E>, PointZ<E>), (o_<> PointZ<E>, Point<E>),
        (_o<> &Point<E>, Point<E>), (_o<> &Point<E>, PointZ<E>),
        (_o<> &PointZ<E>, Point<E>), (_o<> &PointZ<E>, PointZ<E>),

        // The same as above, but replacing &Point<E> with PointRef<E>
        (o_<'r> Point<E>, PointRef<'r, E>),
        (r_<'a, 'b> PointRef<'a, E>, PointRef<'b, E>), (r_<'r> PointRef<'r, E>, &PointZ<E>),
        (o_<'r> PointZ<E>, PointRef<'r, E>),
        (r_<'r> &PointZ<E>, PointRef<'r, E>),
        (_o<'r> PointRef<'r, E>, Point<E>), (_o<'r> PointRef<'r, E>, PointZ<E>),

        // And define trait between &Point<E> and PointRef<E>
        (r_<'r> &Point<E>, PointRef<'r, E>), (r_<'r> PointRef<'r, E>, &Point<E>),
    }
}

matrix! {
    trait = Mul,
    trait_fn = mul,
    output = PointZ<E>,
    output_new = PointZ,
    point_fn = scalar_mul,
    point_assign_fn = scalar_mul_assign,
    pairs = {
        (o_<> Point<E>, &Scalar<E>), (o_<> Point<E>, &ScalarZ<E>),
        (r_<> &Point<E>, &Scalar<E>), (r_<> &Point<E>, &ScalarZ<E>),
        (o_<> PointZ<E>, &Scalar<E>), (o_<> PointZ<E>, &ScalarZ<E>),
        (r_<> &PointZ<E>, &Scalar<E>), (r_<> &PointZ<E>, &ScalarZ<E>),
        (o_<> Point<E>, Scalar<E>), (o_<> Point<E>, ScalarZ<E>),
        (r_<> &Point<E>, Scalar<E>), (r_<> &Point<E>, ScalarZ<E>),
        (o_<> PointZ<E>, Scalar<E>), (o_<> PointZ<E>, ScalarZ<E>),
        (r_<> &PointZ<E>, Scalar<E>), (r_<> &PointZ<E>, ScalarZ<E>),

        // The same as above but replacing &Point with PointRef
        (r_<'p> PointRef<'p, E>, &Scalar<E>), (r_<'p> PointRef<'p, E>, &ScalarZ<E>),
        (r_<'p> PointRef<'p, E>, Scalar<E>), (r_<'p> PointRef<'p, E>, ScalarZ<E>),

        // --- And vice-versa ---

        (_o<> &Scalar<E>, Point<E>), (_o<> &ScalarZ<E>, Point<E>),
        (_r<> &Scalar<E>, &Point<E>), (_r<> &ScalarZ<E>, &Point<E>),
        (_o<> &Scalar<E>, PointZ<E>), (_o<> &ScalarZ<E>, PointZ<E>),
        (_r<> &Scalar<E>, &PointZ<E>), (_r<> &ScalarZ<E>, &PointZ<E>),
        (_o<> Scalar<E>, Point<E>), (_o<> ScalarZ<E>, Point<E>),
        (_r<> Scalar<E>, &Point<E>), (_r<> ScalarZ<E>, &Point<E>),
        (_o<> Scalar<E>, PointZ<E>), (_o<> ScalarZ<E>, PointZ<E>),
        (_r<> Scalar<E>, &PointZ<E>), (_r<> ScalarZ<E>, &PointZ<E>),

        // The same as above but replacing &Point with PointRef
        (_r<'p> &Scalar<E>, PointRef<'p, E>), (_r<'p> &ScalarZ<E>, PointRef<'p, E>),
        (_r<'p> Scalar<E>, PointRef<'p, E>), (_r<'p> ScalarZ<E>, PointRef<'p, E>),
    }
}

matrix! {
    trait = Add,
    trait_fn = add,
    output = ScalarZ<E>,
    output_new = ScalarZ,
    point_fn = add,
    point_assign_fn = add_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, ScalarZ<E>),
        (o_<> Scalar<E>, &Scalar<E>), (o_<> Scalar<E>, &ScalarZ<E>),
        (o_<> ScalarZ<E>, Scalar<E>), (o_<> ScalarZ<E>, ScalarZ<E>),
        (o_<> ScalarZ<E>, &Scalar<E>), (o_<> ScalarZ<E>, &ScalarZ<E>),
        (_o<> &Scalar<E>, Scalar<E>), (_o<> &Scalar<E>, ScalarZ<E>),
        (r_<> &Scalar<E>, &Scalar<E>), (r_<> &Scalar<E>, &ScalarZ<E>),
        (_o<> &ScalarZ<E>, Scalar<E>), (_o<> &ScalarZ<E>, ScalarZ<E>),
        (r_<> &ScalarZ<E>, &Scalar<E>), (r_<> &ScalarZ<E>, &ScalarZ<E>),
    }
}

matrix! {
    trait = Sub,
    trait_fn = sub,
    output = ScalarZ<E>,
    output_new = ScalarZ,
    point_fn = sub,
    point_assign_fn = sub_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, ScalarZ<E>),
        (o_<> Scalar<E>, &Scalar<E>), (o_<> Scalar<E>, &ScalarZ<E>),
        (o_<> ScalarZ<E>, Scalar<E>), (o_<> ScalarZ<E>, ScalarZ<E>),
        (o_<> ScalarZ<E>, &Scalar<E>), (o_<> ScalarZ<E>, &ScalarZ<E>),
        (_o<> &Scalar<E>, Scalar<E>), (_o<> &Scalar<E>, ScalarZ<E>),
        (r_<> &Scalar<E>, &Scalar<E>), (r_<> &Scalar<E>, &ScalarZ<E>),
        (_o<> &ScalarZ<E>, Scalar<E>), (_o<> &ScalarZ<E>, ScalarZ<E>),
        (r_<> &ScalarZ<E>, &Scalar<E>), (r_<> &ScalarZ<E>, &ScalarZ<E>),
    }
}

matrix! {
    trait = Mul,
    trait_fn = mul,
    output = ScalarZ<E>,
    output_new = ScalarZ,
    point_fn = mul,
    point_assign_fn = mul_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, ScalarZ<E>),
        (o_<> Scalar<E>, &Scalar<E>), (o_<> Scalar<E>, &ScalarZ<E>),
        (o_<> ScalarZ<E>, Scalar<E>), (o_<> ScalarZ<E>, ScalarZ<E>),
        (o_<> ScalarZ<E>, &Scalar<E>), (o_<> ScalarZ<E>, &ScalarZ<E>),
        (_o<> &Scalar<E>, Scalar<E>), (_o<> &Scalar<E>, ScalarZ<E>),
        (r_<> &Scalar<E>, &Scalar<E>), (r_<> &Scalar<E>, &ScalarZ<E>),
        (_o<> &ScalarZ<E>, Scalar<E>), (_o<> &ScalarZ<E>, ScalarZ<E>),
        (r_<> &ScalarZ<E>, &Scalar<E>), (r_<> &ScalarZ<E>, &ScalarZ<E>),
    }
}

impl<E: Curve> ops::Neg for Scalar<E> {
    type Output = Scalar<E>;

    fn neg(self) -> Self::Output {
        Scalar::from_raw(self.0.neg()).expect("neg must not produce zero point")
    }
}

impl<E: Curve> ops::Neg for &Scalar<E> {
    type Output = Scalar<E>;

    fn neg(self) -> Self::Output {
        Scalar::from_raw(self.0.neg()).expect("neg must not produce zero point")
    }
}

impl<E: Curve> ops::Neg for ScalarZ<E> {
    type Output = ScalarZ<E>;

    fn neg(self) -> Self::Output {
        ScalarZ::from_raw(self.0.neg())
    }
}

impl<E: Curve> ops::Neg for &ScalarZ<E> {
    type Output = ScalarZ<E>;

    fn neg(self) -> Self::Output {
        ScalarZ::from_raw(self.0.neg())
    }
}

impl<E: Curve> ops::Neg for Point<E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.0.neg_point()).expect("neg must not produce zero point")
    }
}

impl<E: Curve> ops::Neg for &Point<E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.0.neg_point()).expect("neg must not produce zero point")
    }
}

impl<'p, E: Curve> ops::Neg for PointRef<'p, E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.0.neg_point()).expect("neg must not produce zero point")
    }
}

impl<E: Curve> ops::Neg for PointZ<E> {
    type Output = PointZ<E>;

    fn neg(self) -> Self::Output {
        PointZ::from_raw(self.0.neg_point())
    }
}

impl<E: Curve> ops::Neg for &PointZ<E> {
    type Output = PointZ<E>;

    fn neg(self) -> Self::Output {
        PointZ::from_raw(self.0.neg_point())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
struct ScalarFormat<E: Curve> {
    curve_name: Cow<'static, str>,
    #[serde(with = "hex")]
    scalar: ScalarHex<E>,
}

impl<E: Curve> TryFrom<ScalarFormat<E>> for ScalarZ<E> {
    type Error = ConvertParsedScalarError;

    fn try_from(parsed: ScalarFormat<E>) -> Result<Self, Self::Error> {
        if parsed.curve_name != E::curve_name() {
            return Err(ConvertParsedScalarError::MismatchedCurve {
                got: parsed.curve_name,
                expected: E::curve_name(),
            });
        }

        Ok(ScalarZ::from_raw(parsed.scalar.0))
    }
}

impl<E: Curve> From<ScalarZ<E>> for ScalarFormat<E> {
    fn from(s: ScalarZ<E>) -> Self {
        ScalarFormat {
            curve_name: E::curve_name().into(),
            scalar: ScalarHex(s.0),
        }
    }
}

impl<E: Curve> TryFrom<ScalarFormat<E>> for Scalar<E> {
    type Error = ConvertParsedScalarError;

    fn try_from(parsed: ScalarFormat<E>) -> Result<Self, Self::Error> {
        if parsed.curve_name != E::curve_name() {
            return Err(ConvertParsedScalarError::MismatchedCurve {
                got: parsed.curve_name,
                expected: E::curve_name(),
            });
        }

        ScalarZ::from_raw(parsed.scalar.0)
            .ensure_nonzero()
            .ok_or(ConvertParsedScalarError::ZeroScalar)
    }
}

impl<E: Curve> From<Scalar<E>> for ScalarFormat<E> {
    fn from(s: Scalar<E>) -> Self {
        ScalarFormat {
            curve_name: E::curve_name().into(),
            scalar: ScalarHex(s.0),
        }
    }
}

#[derive(Debug, Error)]
enum ConvertParsedScalarError {
    #[error("scalar must not be zero")]
    ZeroScalar,
    #[error("expected scalar of curve {expected}, but got scalar of curve {got}")]
    MismatchedCurve {
        got: Cow<'static, str>,
        expected: &'static str,
    },
}

struct ScalarHex<E: Curve>(E::Scalar);

impl<E: Curve> hex::ToHex for &ScalarHex<E> {
    fn encode_hex<T: iter::FromIterator<char>>(&self) -> T {
        self.0.to_bigint().to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: iter::FromIterator<char>>(&self) -> T {
        self.0.to_bigint().to_bytes().encode_hex_upper()
    }
}

impl<E: Curve> hex::FromHex for ScalarHex<E> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = Vec::<u8>::from_hex(hex)?;
        let big_int = BigInt::from_bytes(&bytes);
        Ok(ScalarHex(E::Scalar::from_bigint(&big_int)))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! assert_operator_defined_for {
        (
            assert_fn = $assert_fn:ident,
            lhs = {},
            rhs = {$($rhs:ty),*},
        ) => {
            // Corner case
        };
        (
            assert_fn = $assert_fn:ident,
            lhs = {$lhs:ty $(, $lhs_tail:ty)*},
            rhs = {$($rhs:ty),*},
        ) => {
            assert_operator_defined_for! {
                assert_fn = $assert_fn,
                lhs = $lhs,
                rhs = {$($rhs),*},
            }
            assert_operator_defined_for! {
                assert_fn = $assert_fn,
                lhs = {$($lhs_tail),*},
                rhs = {$($rhs),*},
            }
        };
        (
            assert_fn = $assert_fn:ident,
            lhs = $lhs:ty,
            rhs = {$($rhs:ty),*},
        ) => {
            $($assert_fn::<E, $lhs, $rhs>());*
        };
    }

    /// Function asserts that P2 can be added to P1 (ie. P1 + P2) and result is PointZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_addition_defined<E, P1, P2>()
    where
        P1: ops::Add<P2, Output = PointZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_addition_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_addition_defined,
                lhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
                rhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
            }
        }
    }

    /// Function asserts that P2 can be subtracted from P1 (ie. P1 - P2) and result is PointZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_subtraction_defined<E, P1, P2>()
    where
        P1: ops::Sub<P2, Output = PointZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_subtraction_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_subtraction_defined,
                lhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
                rhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
            }
        }
    }

    /// Function asserts that M can be multiplied by N (ie. M * N) and result is PointZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_multiplication_defined<E, M, N>()
    where
        M: ops::Mul<N, Output = PointZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_multiplication_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_multiplication_defined,
                lhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
                rhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
            }
            assert_operator_defined_for! {
                assert_fn = assert_point_multiplication_defined,
                lhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
                rhs = {Point<E>, PointZ<E>, &Point<E>, &PointZ<E>, PointRef<E>},
            }
        }
    }

    /// Function asserts that S2 can be added to S1 (ie. S1 + S2) and result is ScalarZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_addition_defined<E, S1, S2>()
    where
        S1: ops::Add<S2, Output = ScalarZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_addition_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_addition_defined,
                lhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
                rhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
            }
        }
    }

    /// Function asserts that S2 can be added to S1 (ie. S1 + S2) and result is ScalarZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_subtraction_defined<E, S1, S2>()
    where
        S1: ops::Sub<S2, Output = ScalarZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_subtraction_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_subtraction_defined,
                lhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
                rhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
            }
        }
    }

    /// Function asserts that S1 can be multiplied by S2 (ie. S1 * S2) and result is ScalarZ.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_multiplication_defined<E, S1, S2>()
    where
        S1: ops::Mul<S2, Output = ScalarZ<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_multiplication_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_multiplication_defined,
                lhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
                rhs = {Scalar<E>, ScalarZ<E>, &Scalar<E>, &ScalarZ<E>},
            }
        }
    }
}
