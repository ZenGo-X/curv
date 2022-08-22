use std::fmt;

use thiserror::Error;

use crate::elliptic::curves::traits::*;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid point (point order ≠ group order)")]
pub struct MismatchedPointOrder(());

impl MismatchedPointOrder {
    pub(super) fn new() -> Self {
        MismatchedPointOrder(())
    }
}

#[derive(Debug, Error)]
pub enum PointFromBytesError {
    #[error("failed to deserialize the point")]
    DeserializationError,
    #[error("invalid point ({0})")]
    InvalidPoint(MismatchedPointOrder),
}

#[derive(Debug, Error)]
pub enum PointFromCoordsError {
    #[error("{}", NotOnCurve)]
    NotOnCurve,
    #[error("invalid point ({0})")]
    InvalidPoint(MismatchedPointOrder),
}

/// Indicates that conversion or computation failed due to occurred zero point
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZeroPointError(());

impl ZeroPointError {
    pub(super) fn new() -> Self {
        ZeroPointError(())
    }
}

impl fmt::Display for ZeroPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nonzero check failed: point is zero")
    }
}

impl std::error::Error for ZeroPointError {}

/// Indicates that conversion or computation failed due to occurred zero scalar
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZeroScalarError(());

impl ZeroScalarError {
    pub(super) fn new() -> Self {
        ZeroScalarError(())
    }
}

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
