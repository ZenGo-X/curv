use std::borrow::Cow;
use std::convert::TryFrom;
use std::iter;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::elliptic::curves::traits::*;
use crate::elliptic::curves::InvalidPoint;

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PointFormat<E: Curve> {
    curve: Cow<'static, str>,
    compressed_point: Box<[u8]>,
    #[serde(skip, default = "PointFormat::<E>::_ph")]
    _ph: PhantomData<E>,
}

impl<E: Curve> PointFormat<E> {
    fn _ph() -> PhantomData<E> {
        PhantomData
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
        let point = E::Point::deserialize(&parsed.compressed_point)
            .or(Err(ConvertParsedPointError::NotOnCurve))?;
        Point::from_raw(point).or(Err(ConvertParsedPointError::InvalidPoint(
            InvalidPoint::MismatchedPointOrder,
        )))
    }
}

impl<E: Curve> From<Point<E>> for PointFormat<E> {
    fn from(point: Point<E>) -> Self {
        Self {
            curve: E::CURVE_NAME.into(),
            compressed_point: point.as_raw().serialize(true).into(),
            _ph: PhantomData,
        }
    }
}

impl<'p, E: Curve> From<PointRef<'p, E>> for PointFormat<E> {
    fn from(point: PointRef<'p, E>) -> Self {
        Self {
            curve: E::CURVE_NAME.into(),
            compressed_point: point.as_raw().serialize(true).into(),
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

#[cfg(test)]
mod serde_tests {
    use crate::elliptic::curves::{
        Bls12_381_1, Bls12_381_2, Curve, ECPoint, ECScalar, Ed25519, Point, Ristretto, Secp256k1,
        Secp256r1,
    };
    use serde_test::{assert_tokens, Configure, Token::*};

    #[test]
    fn test_serde_zero_point() {
        fn generic<E: Curve>(serialized_zero_len: usize) {
            let point = Point::<E>::zero();
            let mut tokens = vec![
                Struct {
                    name: "PointFormat",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("compressed_point"),
            ];
            tokens.push(Seq {
                len: Option::Some(serialized_zero_len),
            });

            for _ in 0..serialized_zero_len {
                tokens.push(U8(0));
            }
            tokens.extend_from_slice(&[SeqEnd, StructEnd]);
            assert_tokens(&point, &tokens);
        }
        generic::<Secp256k1>(1);
        generic::<Secp256r1>(1);
        generic::<Ristretto>(32);
        generic::<Bls12_381_1>(1);
        generic::<Bls12_381_2>(1);
    }

    #[test]
    fn test_serde_zero_ed25519() {
        let point = Point::<Ed25519>::zero();
        let mut tokens = vec![
            Struct {
                name: "PointFormat",
                len: 2,
            },
            Str("curve"),
            Str(Ed25519::CURVE_NAME),
            Str("compressed_point"),
            Seq {
                len: Option::Some(32),
            },
            U8(1),
        ];
        for _ in 0..31 {
            tokens.push(U8(0));
        }
        tokens.extend_from_slice(&[SeqEnd, StructEnd]);

        assert_tokens(&point, &tokens);
    }

    #[test]
    fn test_serde_random_point() {
        fn generic<E: Curve>() {
            let random_point = E::Point::generator_mul(&E::Scalar::random());
            let point: Point<E> = Point::from_raw(random_point).unwrap();
            let serialized = ECPoint::serialize(point.as_raw(), true);
            let mut tokens = vec![
                Struct {
                    name: "PointFormat",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("compressed_point"),
            ];
            tokens.push(Seq {
                len: Option::Some(serialized.len()),
            });

            for i in serialized {
                tokens.push(U8(i));
            }
            tokens.extend_from_slice(&[SeqEnd, StructEnd]);
            assert_tokens(&point.compact(), &tokens);
        }
        generic::<Secp256k1>();
        generic::<Secp256r1>();
        generic::<Ristretto>();
        generic::<Bls12_381_1>();
        generic::<Bls12_381_2>();
    }
}
