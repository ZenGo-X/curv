use std::fmt;

use thiserror::Error;

use crate::elliptic::curves::traits::*;

#[derive(Debug, Error, Clone, PartialEq)]
#[error("invalid point (point order ≠ group order)")]
pub struct MismatchedPointOrder(pub(super) ());

#[derive(Debug, Error)]
pub enum PointZDeserializationError {
    #[error("failed to deserialize the point")]
    DeserializationError,
    #[error("invalid point ({0})")]
    InvalidPoint(MismatchedPointOrder),
}

#[derive(Debug, Error)]
pub enum PointZFromCoordsError {
    #[error("{}", NotOnCurve)]
    NotOnCurve,
    #[error("invalid point ({0})")]
    InvalidPoint(MismatchedPointOrder),
}

/// Indicates that conversion or computation failed due to occurred zero point
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZeroPointError(pub(super) ());

impl fmt::Display for ZeroPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nonzero check failed: point is zero")
    }
}

impl std::error::Error for ZeroPointError {}

/// Indicates that conversion or computation failed due to occurred zero scalar
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZeroScalarError(pub(super) ());

impl fmt::Display for ZeroScalarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nonzero check failed: scalar is zero")
    }
}

impl std::error::Error for ZeroScalarError {}

#[derive(Error, Debug)]
pub enum InvalidPoint {
    #[error("x,y correspond to zero point")]
    ZeroPoint,
    #[error("{}", MismatchedPointOrder(()))]
    MismatchedPointOrder,
}

/// Constructing Point from its coordinates error
#[derive(Debug, Error)]
pub enum PointFromCoordsError {
    #[error("invalid point ({0})")]
    InvalidPoint(InvalidPoint),
    #[error("{}", NotOnCurve)]
    PointNotOnCurve,
}

/// Constructing Point from its (un)compressed representation error
#[derive(Debug, Error)]
pub enum PointFromBytesError {
    #[error("invalid point ({0})")]
    InvalidPoint(InvalidPoint),
    #[error("{0}")]
    Deserialize(#[source] DeserializationError),
}
