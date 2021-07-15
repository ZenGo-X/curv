// NIST P-256 elliptic curve utility functions.

use p256::elliptic_curve::group::prime::PrimeCurveAffine;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

use generic_array::typenum::U32;
use generic_array::GenericArray;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::traits::{ECPoint, ECScalar};
use crate::arithmetic::traits::*;
use crate::elliptic::curves::{Curve, DeserializationError, NotOnCurve, PointCoords};
use crate::BigInt;

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = BigInt::from_bytes(&GROUP_ORDER_BYTES);

    static ref BASE_POINT2_ENCODED: EncodedPoint = {
        let mut g = vec![4_u8];
        g.extend_from_slice(BASE_POINT2_X.as_ref());
        g.extend_from_slice(BASE_POINT2_Y.as_ref());
        EncodedPoint::from_bytes(&g).unwrap()
    };

    static ref BASE_POINT2: Secp256r1Point = Secp256r1Point {
        purpose: "base_point2",
        ge: PK::from_encoded_point(&BASE_POINT2_ENCODED).unwrap(),
    };

    static ref GENERATOR: Secp256r1Point = Secp256r1Point {
        purpose: "generator",
        ge: AffinePoint::generator()
    };
}

/* X coordinate of a point of unknown discrete logarithm.
Computed using a deterministic algorithm with the generator as input.
See test_base_point2 */
const BASE_POINT2_X: [u8; 32] = [
    0x70, 0xf7, 0x2b, 0xba, 0xc4, 0x0e, 0x8a, 0x59, 0x4c, 0x91, 0xa7, 0xba, 0xc3, 0x76, 0x59, 0x27,
    0x89, 0x10, 0x76, 0x4c, 0xd7, 0xc2, 0x0a, 0x7d, 0x65, 0xa5, 0x9a, 0x04, 0xb0, 0xac, 0x2a, 0xde,
];
const BASE_POINT2_Y: [u8; 32] = [
    0x30, 0xe2, 0xfe, 0xb3, 0x8d, 0x82, 0x4e, 0x0e, 0xa2, 0x95, 0x2f, 0x2a, 0x48, 0x5b, 0xbc, 0xdd,
    0x4c, 0x72, 0x8a, 0x74, 0xf4, 0xfa, 0xc7, 0xdc, 0x0d, 0xc9, 0x90, 0x8d, 0x9a, 0x8d, 0xc1, 0xa4,
];
const GROUP_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Secp256r1 {}

pub type SK = Scalar;
pub type PK = AffinePoint;

#[derive(Clone, Debug)]
pub struct Secp256r1Scalar {
    purpose: &'static str,
    fe: zeroize::Zeroizing<SK>,
}

#[derive(Clone, Copy, Debug)]
pub struct Secp256r1Point {
    purpose: &'static str,
    ge: PK,
}

pub type GE = Secp256r1Point;
pub type FE = Secp256r1Scalar;

impl Curve for Secp256r1 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "secp256r1";
}

impl ECScalar for Secp256r1Scalar {
    type Underlying = SK;

    fn random() -> Secp256r1Scalar {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        let gen_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&arr);
        Secp256r1Scalar {
            purpose: "random",
            fe: Scalar::from_bytes_reduced(&gen_arr).into(),
        }
    }

    fn zero() -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "zero",
            fe: Scalar::zero().into(),
        }
    }

    fn is_zero(&self) -> bool {
        bool::from(self.fe.is_zero())
    }

    fn from_bigint(n: &BigInt) -> Secp256r1Scalar {
        let curve_order = Secp256r1Scalar::group_order();
        let n_reduced = n.modulus(&curve_order);
        let mut v = BigInt::to_bytes(&n_reduced);
        const SECRET_KEY_SIZE: usize = 32;

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        let arr: GenericArray<u8, U32> = *GenericArray::from_slice(&v);

        Secp256r1Scalar {
            purpose: "from_bigint",
            fe: Scalar::from_bytes_reduced(&arr).into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        BigInt::from_bytes(self.fe.to_bytes().as_slice())
    }

    fn add(&self, other: &Self) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "add",
            fe: (*self.fe + *other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "mul",
            fe: (*self.fe * *other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> Secp256r1Scalar {
        Secp256r1Scalar {
            purpose: "sub",
            fe: (*self.fe - *other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        Secp256r1Scalar {
            purpose: "sub",
            fe: (-&*self.fe).into(),
        }
    }

    fn invert(&self) -> Option<Secp256r1Scalar> {
        Some(Secp256r1Scalar {
            purpose: "invert",
            fe: Option::<SK>::from(self.fe.invert())?.into(),
        })
    }

    fn add_assign(&mut self, other: &Self) {
        *self.fe += &*other.fe
    }
    fn mul_assign(&mut self, other: &Self) {
        *self.fe *= &*other.fe
    }
    fn sub_assign(&mut self, other: &Self) {
        *self.fe -= &*other.fe
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &SK {
        &self.fe
    }

    fn underlying_mut(&mut self) -> &mut SK {
        &mut self.fe
    }

    fn from_underlying(fe: SK) -> Self {
        Secp256r1Scalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl PartialEq for Secp256r1Scalar {
    fn eq(&self, other: &Secp256r1Scalar) -> bool {
        self.fe == other.fe
    }
}

impl ECPoint for Secp256r1Point {
    type Scalar = Secp256r1Scalar;
    type Underlying = PK;

    fn zero() -> Secp256r1Point {
        Secp256r1Point {
            purpose: "zero",
            ge: AffinePoint::identity(),
        }
    }

    fn is_zero(&self) -> bool {
        bool::from(self.ge.is_identity())
    }

    fn generator() -> &'static Secp256r1Point {
        &GENERATOR
    }

    fn base_point2() -> &'static Secp256r1Point {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Secp256r1Point, NotOnCurve> {
        let mut vec_x = BigInt::to_bytes(x);
        let mut vec_y = BigInt::to_bytes(y);

        const COORDINATE_SIZE: usize = 32;
        if vec_x.len() > COORDINATE_SIZE {
            // x coordinate is too big
            return Err(NotOnCurve);
        }
        if vec_y.len() > COORDINATE_SIZE {
            // y coordinate is too big
            return Err(NotOnCurve);
        }

        if vec_x.len() < COORDINATE_SIZE {
            // pad
            let mut x_buffer = vec![0; COORDINATE_SIZE - vec_x.len()];
            x_buffer.extend_from_slice(&vec_x);
            vec_x = x_buffer
        }
        if vec_y.len() < COORDINATE_SIZE {
            // pad
            let mut y_buffer = vec![0; COORDINATE_SIZE - vec_y.len()];
            y_buffer.extend_from_slice(&vec_y);
            vec_y = y_buffer
        }

        let x_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&vec_x);
        let y_arr: GenericArray<u8, U32> = *GenericArray::from_slice(&vec_y);

        let ge = PK::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x_arr, &y_arr, false,
        ))
        .ok_or(NotOnCurve)?;

        Ok(Secp256r1Point {
            purpose: "from_coords",
            ge,
        })
    }

    fn x_coord(&self) -> Option<BigInt> {
        let encoded = self.ge.to_encoded_point(false);
        let x = BigInt::from_bytes(encoded.x()?.as_slice());
        Some(x)
    }

    fn y_coord(&self) -> Option<BigInt> {
        let encoded = self.ge.to_encoded_point(false);
        let y = BigInt::from_bytes(encoded.y()?.as_slice());
        Some(y)
    }

    fn coords(&self) -> Option<PointCoords> {
        let encoded = self.ge.to_encoded_point(false);
        let x = BigInt::from_bytes(encoded.x()?.as_slice());
        let y = BigInt::from_bytes(encoded.y()?.as_slice());
        Some(PointCoords { x, y })
    }

    fn serialize(&self, compressed: bool) -> Option<Vec<u8>> {
        if self.is_zero() {
            None
        } else {
            Some(self.ge.to_encoded_point(compressed).to_bytes().into())
        }
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| DeserializationError)?;
        Ok(Secp256r1Point {
            purpose: "deserialize",
            ge: AffinePoint::from_encoded_point(&encoded).ok_or(DeserializationError)?,
        })
    }

    fn check_point_order_equals_group_order(&self) -> bool {
        // This curve has cofactor=1 => any nonzero point has order GROUP_ORDER
        !self.is_zero()
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> Secp256r1Point {
        // TODO: p256 v0.5.0 cannot multiply AffinePoint * Scalar, but can multiply
        //  ProjectivePoint * Scalar. It was fixed in v0.9.0
        Secp256r1Point {
            purpose: "scalar_mul",
            ge: (ProjectivePoint::from(self.ge) * *fe.fe).to_affine(),
        }
    }

    fn add_point(&self, other: &Self) -> Self {
        Secp256r1Point {
            purpose: "add_point",
            ge: (ProjectivePoint::from(self.ge) + other.ge).to_affine(),
        }
    }

    fn sub_point(&self, other: &Self) -> Self {
        Secp256r1Point {
            purpose: "sub_point",
            ge: (ProjectivePoint::from(self.ge) - other.ge).to_affine(),
        }
    }

    fn neg_point(&self) -> Self {
        Secp256r1Point {
            purpose: "neg_point",
            ge: -self.ge,
        }
    }

    /// Reference to underlying curve implementation
    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    /// Mutual reference to underlying curve implementation
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    /// Construct a point from its underlying representation
    fn from_underlying(ge: Self::Underlying) -> Self {
        Secp256r1Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl Zeroize for Secp256r1Point {
    fn zeroize(&mut self) {
        self.ge.zeroize()
    }
}

impl PartialEq for Secp256r1Point {
    fn eq(&self, other: &Self) -> bool {
        self.ge == other.ge
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::arithmetic::*;

    use super::{ECPoint, GE};

    #[test]
    fn test_base_point2() {
        /* Show that base_point2() is returning a point of unknown discrete logarithm.
        It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
        as the initial input, until receiving a valid Secp256r1 point. */

        let base_point2 = GE::base_point2();

        let g = GE::generator();
        let hash = Sha256::digest(&g.serialize(true).unwrap());
        let hash = Sha256::digest(&hash);

        assert_eq!(BigInt::from_bytes(&hash), base_point2.x_coord().unwrap());

        // check that base_point2 is indeed on the curve (from_coords() will fail otherwise)
        assert_eq!(
            &GE::from_coords(
                &base_point2.x_coord().unwrap(),
                &base_point2.y_coord().unwrap()
            )
            .unwrap(),
            base_point2
        );
    }
}
