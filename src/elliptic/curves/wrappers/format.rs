use std::borrow::Cow;
use std::convert::TryFrom;
use std::iter;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::elliptic::curves::traits::*;

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ScalarFormat<E: Curve> {
    curve: Cow<'static, str>,
    #[serde(with = "hex")]
    scalar: ScalarHex<E>,
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

        Ok(Scalar::from_raw(parsed.scalar.0))
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

struct ScalarHex<E: Curve>(E::Scalar);

impl<E: Curve> hex::ToHex for &ScalarHex<E> {
    fn encode_hex<T: iter::FromIterator<char>>(&self) -> T {
        self.0.serialize().encode_hex()
    }

    fn encode_hex_upper<T: iter::FromIterator<char>>(&self) -> T {
        self.0.serialize().encode_hex_upper()
    }
}

impl<E: Curve> hex::FromHex for ScalarHex<E> {
    type Error = ScalarFromhexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = Vec::from_hex(hex).map_err(ScalarFromhexError::InvalidHex)?;
        E::Scalar::deserialize(&bytes)
            .or(Err(ScalarFromhexError::InvalidScalar))
            .map(ScalarHex)
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

#[derive(Debug, Error)]
pub enum ScalarFromhexError {
    #[error("scalar contains invalid hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("scalar is not valid")]
    InvalidScalar,
}
