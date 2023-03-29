use std::ops::Deref;

use generic_array::GenericArray;

use crate::elliptic::curves::{Curve, ECScalar, Scalar};

/// Encoded scalar
pub struct EncodedScalar<E: Curve> {
    bytes: GenericArray<u8, <E::Scalar as ECScalar>::ScalarLength>,
}

impl<E: Curve> Deref for EncodedScalar<E> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes.as_ref()
    }
}

impl<'s, E: Curve> From<&'s Scalar<E>> for EncodedScalar<E> {
    fn from(s: &'s Scalar<E>) -> Self {
        Self {
            bytes: s.as_raw().serialize(),
        }
    }
}

impl<E: Curve> From<Scalar<E>> for EncodedScalar<E> {
    fn from(s: Scalar<E>) -> Self {
        Self::from(&s)
    }
}
