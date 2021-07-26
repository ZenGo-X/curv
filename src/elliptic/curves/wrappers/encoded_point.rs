use std::ops::Deref;

use crate::elliptic::curves::{Curve, ECPoint};

/// Point encoded in (un)compressed form
pub struct EncodedPoint<E: Curve>(pub(super) EncodedPointChoice<E>);

pub(super) enum EncodedPointChoice<E: Curve> {
    Compressed(<E::Point as ECPoint>::CompressedPoint),
    Uncompressed(<E::Point as ECPoint>::UncompressedPoint),
}

impl<E: Curve> Deref for EncodedPoint<E> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            EncodedPointChoice::Compressed(bytes) => bytes.as_ref(),
            EncodedPointChoice::Uncompressed(bytes) => bytes.as_ref(),
        }
    }
}
