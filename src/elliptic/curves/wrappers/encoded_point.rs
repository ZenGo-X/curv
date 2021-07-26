use std::ops::Deref;

use crate::elliptic::curves::{Curve, ECPoint};

/// Point encoded in (un)compressed form
pub enum EncodedPoint<E: Curve> {
    Compressed(<E::Point as ECPoint>::CompressedPoint),
    Uncompressed(<E::Point as ECPoint>::UncompressedPoint),
}

impl<E: Curve> Deref for EncodedPoint<E> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Compressed(bytes) => bytes.as_ref(),
            Self::Uncompressed(bytes) => bytes.as_ref(),
        }
    }
}
