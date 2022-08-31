/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::fmt;

use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use typenum::Unsigned;
use zeroize::Zeroize;

use crate::BigInt;

/// Elliptic curve implementation
///
/// Refers to according implementation of [ECPoint] and [ECScalar].
pub trait Curve: PartialEq + Clone + fmt::Debug + Sync + Send + 'static {
    type Point: ECPoint<Scalar = Self::Scalar>;
    type Scalar: ECScalar;

    /// Canonical name for this curve
    const CURVE_NAME: &'static str;
}

/// Scalar value modulus [group order](Self::group_order)
///
/// ## Note
/// This is a low-level trait, you should not use it directly. See wrappers [Point], [Scalar].
///
/// [Point]: super::wrappers::Point
/// [Scalar]: super::wrappers::Scalar
///
/// Trait exposes various methods to manipulate scalars. Scalar can be zero. Scalar must zeroize its
/// value on drop.
pub trait ECScalar: Clone + PartialEq + fmt::Debug + Send + Sync + 'static {
    /// Underlying scalar type that can be retrieved in case of missing methods in this trait
    type Underlying;

    // TODO: Replace with const generics once https://github.com/rust-lang/rust/issues/60551 is resolved
    /// The byte length of serialized scalar
    type ScalarLength: ArrayLength<u8> + Unsigned;

    /// Samples a random scalar
    fn random() -> Self;

    /// Constructs a zero scalar
    fn zero() -> Self;
    /// Checks if the scalar equals to zero
    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    /// Constructs a scalar `n % group_order`
    fn from_bigint(n: &BigInt) -> Self;
    /// Converts a scalar to BigInt
    fn to_bigint(&self) -> BigInt;
    /// Serializes scalar into bytes
    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength>;
    /// Deserializes scalar from bytes
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError>;

    /// Calculates `(self + other) mod group_order`
    fn add(&self, other: &Self) -> Self;
    /// Calculates `(self * other) mod group_order`
    fn mul(&self, other: &Self) -> Self;
    /// Calculates `(self - other) mod group_order`
    fn sub(&self, other: &Self) -> Self;
    /// Calculates `-self mod group_order`
    fn neg(&self) -> Self;
    /// Calculates `self^-1 (mod group_order)`, returns None if self equals to zero
    fn invert(&self) -> Option<Self>;
    /// Calculates `(self + other) mod group_order`, and assigns result to `self`
    fn add_assign(&mut self, other: &Self) {
        *self = self.add(other)
    }
    /// Calculates `(self * other) mod group_order`, and assigns result to `self`
    fn mul_assign(&mut self, other: &Self) {
        *self = self.mul(other)
    }
    /// Calculates `(self - other) mod group_order`, and assigns result to `self`
    fn sub_assign(&mut self, other: &Self) {
        *self = self.sub(other)
    }
    /// Calculates `-self mod group_order`, and assigns result to `self`
    fn neg_assign(&mut self) {
        *self = self.neg()
    }

    /// Returns an order of generator point
    fn group_order() -> &'static BigInt;

    /// Returns a reference to underlying scalar value
    fn underlying_ref(&self) -> &Self::Underlying;
    /// Returns a mutable reference to underlying scalar value
    fn underlying_mut(&mut self) -> &mut Self::Underlying;
    /// Constructs a scalar from underlying value
    fn from_underlying(u: Self::Underlying) -> Self;
}

/// Point on elliptic curve
///
/// ## Note
/// This is a low-level trait, you should not use it directly. See [Point], [Scalar].
///
/// [Point]: super::wrappers::Point
/// [Scalar]: super::wrappers::Scalar
///
/// Trait exposes various methods that make elliptic curve arithmetic. The point can
/// be [zero](ECPoint::zero). Unlike [ECScalar], ECPoint isn't required to zeroize its value on drop,
/// but it implements [Zeroize] trait so you can force zeroizing policy on your own.
pub trait ECPoint: Zeroize + Clone + PartialEq + fmt::Debug + Sync + Send + 'static {
    /// Scalar value the point can be multiplied at
    type Scalar: ECScalar;
    /// Underlying curve implementation that can be retrieved in case of missing methods in this trait
    type Underlying;

    /// The byte length of point serialized in compressed form
    type CompressedPointLength: ArrayLength<u8> + Unsigned;
    /// The byte length of point serialized in uncompressed form
    type UncompressedPointLength: ArrayLength<u8> + Unsigned;

    /// Zero point
    ///
    /// Zero point is usually denoted as O. It's curve neutral element, i.e. `forall A. A + O = A`.
    /// Weierstrass and Montgomery curves employ special "point at infinity" to add neutral elements,
    /// such points don't have coordinates (i.e. [from_coords], [x_coord], [y_coord] return `None`).
    /// Edwards curves' neutral element has coordinates.
    ///
    /// [from_coords]: Self::from_coords
    /// [x_coord]: Self::x_coord
    /// [y_coord]: Self::y_coord
    fn zero() -> Self;

    /// Returns `true` if point is a neutral element
    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    /// Curve generator
    ///
    /// Returns a static reference at actual value because in most cases reference value is fine.
    /// Use `.clone()` if you need to take it by value, i.e. `ECPoint::generator().clone()`
    fn generator() -> &'static Self;
    /// Curve second generator
    ///
    /// We provide an alternative generator value and prove that it was picked randomly
    fn base_point2() -> &'static Self;

    /// Constructs a curve point from its coordinates
    ///
    /// Returns error if x, y are not on curve
    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, NotOnCurve>;
    /// Returns `x` coordinate of the point, or `None` if point is at infinity
    fn x_coord(&self) -> Option<BigInt>;
    /// Returns `y` coordinate of the point, or `None` if point is at infinity
    fn y_coord(&self) -> Option<BigInt>;
    /// Returns point coordinates (`x` and `y`), or `None` if point is at infinity
    fn coords(&self) -> Option<PointCoords>;

    /// Serializes point into bytes in compressed
    ///
    /// Serialization must always succeed even if it's point at infinity.
    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength>;
    /// Serializes point into bytes in uncompressed
    ///
    /// Serialization must always succeed even if it's point at infinity.
    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength>;
    /// Deserializes point from bytes
    ///
    /// Whether point in compressed or uncompressed form will be deducted from its size
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError>;

    /// Checks that order of this point equals to [group order](ECScalar::group_order)
    ///
    /// Generally, point might be composition of different subgroups points: `P = sG + kT` (`G` —
    /// curve generator of order `q`=[group_order](ECScalar::group_order), `T` — generator of smaller
    /// order). This function ensures that the point is of order `q`, ie. of form: `P = sG`.
    ///
    /// For curves with co-factor ≠ 1, following check must be carried out:
    ///
    /// ```text
    /// P ≠ 0 ∧ qP ≠ 0
    /// ```
    ///
    /// For curves with co-factor = 1, the check above can be reduced to: `P ≠ 0`.
    fn check_point_order_equals_group_order(&self) -> bool {
        let mut self_at_q = self.scalar_mul(&Self::Scalar::from_bigint(
            &(Self::Scalar::group_order() - 1),
        ));
        self_at_q.add_point_assign(self);
        !self.is_zero() && self_at_q.is_zero()
    }

    /// Multiplies the point at scalar value
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
    /// Multiplies curve generator at given scalar
    ///
    /// Basically, it's the same as `ECPoint::generator().scalar_mul(&s)`, but can be more efficient
    /// because most curve libs have constant time high performance generator multiplication.
    fn generator_mul(scalar: &Self::Scalar) -> Self {
        Self::generator().scalar_mul(scalar)
    }
    /// Adds two points
    fn add_point(&self, other: &Self) -> Self;
    /// Substrates `other` from `self`
    fn sub_point(&self, other: &Self) -> Self;
    /// Negates point
    fn neg_point(&self) -> Self;

    /// Multiplies the point at scalar value, assigns result to `self`
    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        *self = self.scalar_mul(scalar)
    }
    /// Adds two points, assigns result to `self`
    fn add_point_assign(&mut self, other: &Self) {
        *self = self.add_point(other)
    }
    /// Substrates `other` from `self`, assigns result to `self`
    fn sub_point_assign(&mut self, other: &Self) {
        *self = self.sub_point(other)
    }
    /// Negates point, assigns result to `self`
    fn neg_point_assign(&mut self) {
        *self = self.neg_point()
    }

    /// Reference to underlying curve implementation
    fn underlying_ref(&self) -> &Self::Underlying;
    /// Mutual reference to underlying curve implementation
    fn underlying_mut(&mut self) -> &mut Self::Underlying;
    /// Construct a point from its underlying representation
    fn from_underlying(u: Self::Underlying) -> Self;
}

/// Affine coordinates of a point
#[derive(Serialize, Deserialize)]
pub struct PointCoords {
    pub x: BigInt,
    pub y: BigInt,
}

#[derive(Debug)]
pub struct DeserializationError;

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to deserialize the point/scalar")
    }
}

impl std::error::Error for DeserializationError {}

#[derive(Debug)]
pub struct NotOnCurve;

impl fmt::Display for NotOnCurve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "point not on the curve")
    }
}

impl std::error::Error for NotOnCurve {}
