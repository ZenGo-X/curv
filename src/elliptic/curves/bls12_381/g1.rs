/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::fmt;

use ff_zeroize::PrimeField;
use generic_array::GenericArray;
use pairing_plus::bls12_381::{G1Compressed, G1Uncompressed, G1};
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::{CurveAffine, CurveProjective, Engine};
use pairing_plus::{EncodedPoint, SubgroupCheck};
use zeroize::Zeroize;

use crate::arithmetic::traits::*;
use crate::elliptic::curves::traits::*;
use crate::BigInt;

use super::scalar::FieldScalar;

lazy_static::lazy_static! {
    static ref GENERATOR: G1Point = G1Point {
        purpose: "generator",
        ge: PK::one(),
    };

    static ref BASE_POINT2: G1Point = {
        const BASE_POINT2: [u8; 96] = [
            10, 18, 122, 36, 178, 251, 236, 31, 139, 88, 242, 163, 21, 198, 168, 208, 122, 195,
            135, 122, 7, 153, 197, 255, 160, 0, 89, 138, 39, 245, 105, 108, 99, 113, 78, 70, 130,
            172, 183, 57, 170, 180, 39, 32, 173, 29, 238, 62, 13, 166, 109, 90, 181, 17, 76, 247,
            26, 155, 130, 211, 18, 42, 235, 137, 225, 184, 210, 140, 54, 83, 233, 228, 226, 70,
            194, 50, 55, 116, 229, 2, 115, 227, 223, 31, 165, 39, 191, 209, 49, 127, 106, 196, 123,
            71, 70, 243,
        ];
        let mut point = G1Uncompressed::empty();
        point.as_mut().copy_from_slice(&BASE_POINT2);
        G1Point {
            purpose: "base_point2",
            ge: point.into_affine().expect("invalid base_point"),
        }
    };
}

pub const SECRET_KEY_SIZE: usize = 32;
pub const COMPRESSED_SIZE: usize = 48;

pub type PK = <pairing_plus::bls12_381::Bls12 as Engine>::G1Affine;

/// Bls12-381-1 (G1) curve implementation based on [pairing_plus] library
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Bls12_381_1 {}

#[derive(Clone, Copy)]
pub struct G1Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE1 = G1Point;

impl Curve for Bls12_381_1 {
    type Point = GE1;
    type Scalar = FieldScalar;

    const CURVE_NAME: &'static str = "bls12_381_1";
}

impl ECPoint for G1Point {
    type Scalar = FieldScalar;
    type Underlying = PK;

    type CompressedPointLength = typenum::U48;
    type UncompressedPointLength = typenum::U96;

    fn zero() -> G1Point {
        G1Point {
            purpose: "zero",
            ge: PK::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_zero()
    }

    fn generator() -> &'static G1Point {
        &GENERATOR
    }

    fn base_point2() -> &'static G1Point {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<G1Point, NotOnCurve> {
        let vec_x = x.to_bytes();
        let vec_y = y.to_bytes();
        if vec_x.len() > COMPRESSED_SIZE || vec_y.len() > COMPRESSED_SIZE {
            return Err(NotOnCurve);
        }
        let mut uncompressed = [0u8; 2 * COMPRESSED_SIZE];
        uncompressed[COMPRESSED_SIZE - vec_x.len()..COMPRESSED_SIZE].copy_from_slice(&vec_x);
        uncompressed[(2 * COMPRESSED_SIZE) - vec_y.len()..].copy_from_slice(&vec_y);
        debug_assert_eq!(x, &BigInt::from_bytes(&uncompressed[..COMPRESSED_SIZE]));
        debug_assert_eq!(y, &BigInt::from_bytes(&uncompressed[COMPRESSED_SIZE..]));

        let mut point = G1Uncompressed::empty();
        point.as_mut().copy_from_slice(&uncompressed);

        Ok(G1Point {
            purpose: "from_coords",
            ge: point.into_affine().map_err(|_| NotOnCurve)?,
        })
    }

    fn x_coord(&self) -> Option<BigInt> {
        if self.is_zero() {
            None
        } else {
            let uncompressed = G1Uncompressed::from_affine(self.ge);
            let x_coord = &uncompressed.as_ref()[0..COMPRESSED_SIZE];
            let bn = BigInt::from_bytes(x_coord);
            Some(bn)
        }
    }

    fn y_coord(&self) -> Option<BigInt> {
        if self.is_zero() {
            None
        } else {
            let uncompressed = G1Uncompressed::from_affine(self.ge);
            let y_coord = &uncompressed.as_ref()[COMPRESSED_SIZE..COMPRESSED_SIZE * 2];
            let bn = BigInt::from_bytes(y_coord);
            Some(bn)
        }
    }

    fn coords(&self) -> Option<PointCoords> {
        if self.is_zero() {
            None
        } else {
            let uncompressed = G1Uncompressed::from_affine(self.ge);
            let x = &uncompressed.as_ref()[0..COMPRESSED_SIZE];
            let y = &uncompressed.as_ref()[COMPRESSED_SIZE..COMPRESSED_SIZE * 2];
            let x = BigInt::from_bytes(x);
            let y = BigInt::from_bytes(y);
            Some(PointCoords { x, y })
        }
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        *GenericArray::from_slice(G1Compressed::from_affine(self.ge).as_ref())
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        *GenericArray::from_slice(G1Uncompressed::from_affine(self.ge).as_ref())
    }

    fn deserialize(bytes: &[u8]) -> Result<G1Point, DeserializationError> {
        if bytes.len() == COMPRESSED_SIZE {
            let mut compressed = G1Compressed::empty();
            compressed.as_mut().copy_from_slice(bytes);
            Ok(G1Point {
                purpose: "deserialize",
                ge: compressed.into_affine().map_err(|_| DeserializationError)?,
            })
        } else if bytes.len() == 2 * COMPRESSED_SIZE {
            let mut uncompressed = G1Uncompressed::empty();
            uncompressed.as_mut().copy_from_slice(bytes);
            Ok(G1Point {
                purpose: "deserialize",
                ge: uncompressed
                    .into_affine()
                    .map_err(|_| DeserializationError)?,
            })
        } else {
            Err(DeserializationError)
        }
    }

    fn check_point_order_equals_group_order(&self) -> bool {
        !self.is_zero() && self.ge.in_subgroup()
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> G1Point {
        let result = self.ge.mul(scalar.underlying_ref().into_repr());
        G1Point {
            purpose: "scalar_mul",
            ge: result.into_affine(),
        }
    }

    fn add_point(&self, other: &Self) -> G1Point {
        let mut result = G1::from(self.ge);
        result.add_assign_mixed(&other.ge);
        G1Point {
            purpose: "add_point",
            ge: result.into_affine(),
        }
    }

    fn sub_point(&self, other: &Self) -> G1Point {
        let mut result = G1::from(self.ge);
        result.sub_assign_mixed(&other.ge);
        G1Point {
            purpose: "sub_point",
            ge: result.into_affine(),
        }
    }

    fn neg_point(&self) -> Self {
        let mut result = self.ge;
        result.negate();
        G1Point {
            purpose: "neg",
            ge: result,
        }
    }

    fn neg_point_assign(&mut self) {
        self.ge.negate();
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> G1Point {
        G1Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl G1Point {
    /// Converts message to G1 point.
    ///
    /// Uses [expand_message_xmd][xmd] based on sha256.
    ///
    /// [xmd]: https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-10.html#name-expand_message_xmd-2
    pub fn hash_to_curve(message: &[u8]) -> Self {
        let cs = &[1u8];
        let point = <G1 as HashToCurve<ExpandMsgXmd<old_sha2::Sha256>>>::hash_to_curve(message, cs);
        G1Point {
            purpose: "hash_to_curve",
            ge: point.into_affine(),
        }
    }
}

impl fmt::Debug for G1Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, uncompressed: {:?} }}",
            self.purpose,
            hex::encode(self.serialize_uncompressed()),
        )
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &G1Point) -> bool {
        self.ge == other.ge
    }
}

impl Zeroize for G1Point {
    fn zeroize(&mut self) {
        self.ge.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use pairing_plus::bls12_381::{G1Uncompressed, G1};
    use pairing_plus::hash_to_curve::HashToCurve;
    use pairing_plus::hash_to_field::ExpandMsgXmd;
    use pairing_plus::{CurveProjective, SubgroupCheck};

    use super::{ECPoint, GE1};

    #[test]
    fn base_point2_nothing_up_my_sleeve() {
        // Generate base_point2
        let cs = &[1u8];
        let msg = &[1u8];
        let point = <G1 as HashToCurve<ExpandMsgXmd<old_sha2::Sha256>>>::hash_to_curve(msg, cs)
            .into_affine();
        assert!(point.in_subgroup());

        // Print in uncompressed form
        use pairing_plus::EncodedPoint;
        let point_uncompressed = G1Uncompressed::from_affine(point);
        println!("Uncompressed base_point2: {:?}", point_uncompressed);

        // Check that ECPoint::base_point2() returns generated point
        let base_point2: &GE1 = ECPoint::base_point2();
        assert_eq!(point, base_point2.ge);
    }
}
