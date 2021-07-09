use std::borrow::Cow;
use std::convert::TryFrom;
use std::iter;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::arithmetic::*;
use crate::elliptic::curves::traits::*;

use super::{
    error::{InvalidPoint, MismatchedPointOrder, PointFromCoordsError, PointZFromCoordsError},
    *,
};

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PointFormat<E: Curve> {
    curve: Cow<'static, str>,
    point: Option<PointCoords>,
    #[serde(skip, default = "PointFormat::<E>::_ph")]
    _ph: PhantomData<E>,
}

impl<E: Curve> PointFormat<E> {
    fn _ph() -> PhantomData<E> {
        PhantomData
    }
}

impl<E: Curve> TryFrom<PointFormat<E>> for PointZ<E> {
    type Error = ConvertParsedPointError;
    fn try_from(parsed: PointFormat<E>) -> Result<Self, ConvertParsedPointError> {
        if parsed.curve != E::CURVE_NAME {
            return Err(ConvertParsedPointError::MismatchedCurve {
                expected: E::CURVE_NAME,
                got: parsed.curve,
            });
        }
        match parsed.point {
            None => Ok(PointZ::zero()),
            Some(coords) => match PointZ::from_coords(&coords.x, &coords.y) {
                Ok(p) => Ok(p),
                Err(PointZFromCoordsError::NotOnCurve) => Err(ConvertParsedPointError::NotOnCurve),
                Err(PointZFromCoordsError::InvalidPoint(MismatchedPointOrder(()))) => Err(
                    ConvertParsedPointError::InvalidPoint(InvalidPoint::MismatchedPointOrder),
                ),
            },
        }
    }
}

impl<E: Curve> From<PointZ<E>> for PointFormat<E> {
    fn from(point: PointZ<E>) -> Self {
        Self {
            curve: E::CURVE_NAME.into(),
            point: point.coords(),
            _ph: PhantomData,
        }
    }
}

impl<E: Curve> TryFrom<PointFormat<E>> for Point<E> {
    type Error = ConvertParsedPointError;
    fn try_from(parsed: PointFormat<E>) -> Result<Self, ConvertParsedPointError> {
        if parsed.curve != E::CURVE_NAME {
            return Err(ConvertParsedPointError::MismatchedCurve {
                expected: E::CURVE_NAME,
                got: parsed.curve,
            });
        }
        match parsed.point {
            None => Err(ConvertParsedPointError::InvalidPoint(
                InvalidPoint::ZeroPoint,
            )),
            Some(coords) => match Point::from_coords(&coords.x, &coords.y) {
                Ok(p) => Ok(p),
                Err(PointFromCoordsError::PointNotOnCurve) => {
                    Err(ConvertParsedPointError::NotOnCurve)
                }
                Err(PointFromCoordsError::InvalidPoint(reason)) => {
                    Err(ConvertParsedPointError::InvalidPoint(reason))
                }
            },
        }
    }
}

impl<E: Curve> From<Point<E>> for PointFormat<E> {
    fn from(point: Point<E>) -> Self {
        Self {
            curve: E::CURVE_NAME.into(),
            point: Some(point.coords()),
            _ph: PhantomData,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConvertParsedPointError {
    #[error("invalid point ({0})")]
    InvalidPoint(InvalidPoint),
    #[error("expected point of curve {expected}, but got point of curve {got}")]
    MismatchedCurve {
        got: Cow<'static, str>,
        expected: &'static str,
    },
    #[error("point not on the curve: x,y don't satisfy curve equation")]
    NotOnCurve,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ScalarFormat<E: Curve> {
    curve: Cow<'static, str>,
    #[serde(with = "hex")]
    scalar: ScalarHex<E>,
}

impl<E: Curve> TryFrom<ScalarFormat<E>> for ScalarZ<E> {
    type Error = ConvertParsedScalarError;

    fn try_from(parsed: ScalarFormat<E>) -> Result<Self, Self::Error> {
        if parsed.curve != E::CURVE_NAME {
            return Err(ConvertParsedScalarError::MismatchedCurve {
                got: parsed.curve,
                expected: E::CURVE_NAME,
            });
        }

        Ok(ScalarZ::from_raw(parsed.scalar.0))
    }
}

impl<E: Curve> From<ScalarZ<E>> for ScalarFormat<E> {
    fn from(s: ScalarZ<E>) -> Self {
        ScalarFormat {
            curve: E::CURVE_NAME.into(),
            scalar: ScalarHex(s.into_raw()),
        }
    }
}

impl<E: Curve> TryFrom<ScalarFormat<E>> for Scalar<E> {
    type Error = ConvertParsedScalarError;

    fn try_from(parsed: ScalarFormat<E>) -> Result<Self, Self::Error> {
        if parsed.curve != E::CURVE_NAME {
            return Err(ConvertParsedScalarError::MismatchedCurve {
                got: parsed.curve,
                expected: E::CURVE_NAME,
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
            curve: E::CURVE_NAME.into(),
            scalar: ScalarHex(s.into_raw()),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConvertParsedScalarError {
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
