use std::ops::Deref;

use generic_array::GenericArray;

use crate::elliptic::curves::{Curve, ECPoint};

/// Point encoded in (un)compressed form
pub struct EncodedPoint<E: Curve>(pub(super) EncodedPointChoice<E>);

pub(super) enum EncodedPointChoice<E: Curve> {
    Compressed(GenericArray<u8, <E::Point as ECPoint>::CompressedPointLength>),
    Uncompressed(GenericArray<u8, <E::Point as ECPoint>::UncompressedPointLength>),
}

impl<E: Curve> Deref for EncodedPoint<E> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<E: Curve> AsRef<[u8]> for EncodedPoint<E> {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            EncodedPointChoice::Compressed(bytes) => bytes.as_ref(),
            EncodedPointChoice::Uncompressed(bytes) => bytes.as_ref(),
        }
    }
}
