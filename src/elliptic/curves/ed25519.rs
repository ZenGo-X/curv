/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// paper: https://ed25519.cr.yp.to/ed25519-20110926.pdf
// based on https://docs.rs/curve25519-dalek/3.2.0/curve25519_dalek/index.html
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

use super::{
    traits::{ECPoint, ECScalar},
    Curve, DeserializationError, NotOnCurve, PointCoords,
};
use crate::{arithmetic::traits::*, cryptographic_primitives::hashing::Digest, BigInt};
use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use generic_array::GenericArray;
use std::{convert::TryInto, ptr, str, sync::atomic};
use zeroize::{Zeroize, Zeroizing};

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = Ed25519Scalar {
        purpose: "intermediate group_order",
        fe: constants::BASEPOINT_ORDER.into()
    }.to_bigint();

    static ref ZERO: Ed25519Point = Ed25519Point {
        purpose: "zero",
        ge: EdwardsPoint::identity(),
    };

    static ref FE_ZERO: SK = Scalar::zero();

    static ref BASE_POINT2: Ed25519Point = {
        let bytes = GENERATOR.serialize_compressed();
        let hashed = sha2::Sha256::digest(bytes.as_ref());
        let hashed_twice = sha2::Sha256::digest(&hashed);
        let p = CompressedEdwardsY::from_slice(&hashed_twice).decompress().unwrap();
        let eight = Scalar::from(8u8);
        Ed25519Point {
            purpose: "base_point2",
            ge: p * eight,
        }
    };
}

const GENERATOR: Ed25519Point = Ed25519Point {
    purpose: "generator",
    ge: constants::ED25519_BASEPOINT_POINT,
};

const TWO_TIMES_SECRET_KEY_SIZE: usize = 64;

/// Alias to [Edwards point](EdwardsPoint)
pub type PK = EdwardsPoint;
pub type SK = Scalar;

/// Ed25519 curve implementation based on [cryptoxide] library
///
/// ## Implementation notes
/// * x coordinate
///
///   Underlying library doesn't expose x coordinate of curve point, but there's an algorithm
///   recovering x coordinate of ed25519 point from its y coordinate. Every time you call
///   `.x_coord()` or `from_coords()`, it takes y coordinate and runs `xrecover(y)` underhood. Keep
///   in mind that `xrecover` is quite expensive operation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ed25519 {}

#[derive(Clone, Debug)]
pub struct Ed25519Scalar {
    #[allow(dead_code)]
    purpose: &'static str,
    fe: Zeroizing<SK>,
}

#[derive(Clone, Debug, Copy)]
pub struct Ed25519Point {
    #[allow(dead_code)]
    purpose: &'static str,
    ge: PK,
}

pub type GE = Ed25519Point;
pub type FE = Ed25519Scalar;

impl Curve for Ed25519 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "ed25519";
}

impl ECScalar for Ed25519Scalar {
    type Underlying = SK;

    type ScalarLength = typenum::U32;

    // we chose to multiply by 8 (co-factor) all group elements to work in the prime order sub group.
    // each random fe is having its 3 first bits zeroed
    fn random() -> Ed25519Scalar {
        let scalar = Scalar::random(&mut rand::thread_rng());
        Ed25519Scalar {
            purpose: "random",
            fe: Zeroizing::new(scalar),
        }
    }

    fn zero() -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "zero",
            fe: (*FE_ZERO).into(),
        }
    }

    fn is_zero(&self) -> bool {
        *self.fe == *FE_ZERO
    }

    fn from_bigint(n: &BigInt) -> Ed25519Scalar {
        let mut v = BigInt::to_bytes(n);
        v.truncate(TWO_TIMES_SECRET_KEY_SIZE);

        let mut template = [0u8; TWO_TIMES_SECRET_KEY_SIZE];
        template[TWO_TIMES_SECRET_KEY_SIZE - v.len()..].copy_from_slice(&v);
        template.reverse();
        let scalar = Scalar::from_bytes_mod_order_wide(&template);
        Ed25519Scalar {
            purpose: "from_bigint",
            fe: scalar.into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        let mut t = self.fe.to_bytes();
        t.reverse();
        BigInt::from_bytes(&t)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        GenericArray::from(self.fe.to_bytes())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| DeserializationError)?;
        Ok(Ed25519Scalar {
            purpose: "deserialize",
            fe: SK::from_bits(arr).into(),
        })
    }

    fn add(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "add",
            fe: (*self.fe + *other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "mul",
            fe: (*self.fe * *other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "sub",
            fe: (*self.fe - *other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        Ed25519Scalar {
            purpose: "neg",
            fe: (-&*self.fe).into(),
        }
    }

    fn invert(&self) -> Option<Ed25519Scalar> {
        if self.is_zero() {
            None
        } else {
            Some(Ed25519Scalar {
                purpose: "invert",
                fe: self.fe.invert().into(),
            })
        }
    }

    fn add_assign(&mut self, other: &Self) {
        *self.fe += &*other.fe;
    }
    fn mul_assign(&mut self, other: &Self) {
        *self.fe *= &*other.fe;
    }
    fn sub_assign(&mut self, other: &Self) {
        *self.fe -= &*other.fe;
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }
    fn from_underlying(fe: Self::Underlying) -> Ed25519Scalar {
        Ed25519Scalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl PartialEq for Ed25519Scalar {
    fn eq(&self, other: &Ed25519Scalar) -> bool {
        self.fe == other.fe
    }
}

impl PartialEq for Ed25519Point {
    fn eq(&self, other: &Ed25519Point) -> bool {
        self.ge == other.ge
    }
}

impl Zeroize for Ed25519Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(&mut self.ge, GENERATOR.ge) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for Ed25519Point {
    type Underlying = PK;
    type Scalar = Ed25519Scalar;

    type CompressedPointLength = typenum::U32;
    type UncompressedPointLength = typenum::U32;

    fn zero() -> Self {
        *ZERO
    }

    fn is_zero(&self) -> bool {
        self == &*ZERO
    }

    fn generator() -> &'static Self {
        &GENERATOR
    }

    fn base_point2() -> &'static Self {
        &BASE_POINT2
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, NotOnCurve> {
        let is_odd = x.is_odd();
        let expected_x = xrecover(y, is_odd);
        if &expected_x != x {
            return Err(NotOnCurve);
        }
        let y_bytes = y.to_bytes();
        let mut padded = match y_bytes.len() {
            n if n > 32 => return Err(NotOnCurve),
            32 => y_bytes,
            _ => {
                let mut padding = vec![0; 32 - y_bytes.len()];
                padding.extend_from_slice(&y_bytes);
                padding
            }
        };
        // BigInt uses Big-Endian but the 25519 libraries use Little-Endian, so we reverse the bytes
        padded.reverse();
        // All curve25519 libs serialize a point by taking the `y` coordinate,
        // and putting the is_odd flag of the `x` coordinate in the most significant bit.
        padded[31] |= (is_odd as u8) << 7;

        Self::deserialize(&padded).map_err(|_e| NotOnCurve)
    }

    fn x_coord(&self) -> Option<BigInt> {
        self.coords().map(|c| c.x)
    }

    fn y_coord(&self) -> Option<BigInt> {
        let mut bytes = self.ge.compress().to_bytes();
        // According to https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2
        // the most significant bit in a point encoding says if x is even or odd
        // so we clear that bit as it's not part of the field element.
        bytes[31] &= 0b01111111;

        // reverse because BigInt is Big-Endian while the field element is Little-Endian
        bytes.reverse();
        Some(BigInt::from_bytes(&bytes))
    }

    fn coords(&self) -> Option<PointCoords> {
        let mut bytes = self.ge.compress().to_bytes();
        // According to https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2
        // the most significant bit in a point encoding says if x is odd or even
        let is_odd = (bytes[31] >> 7) == 1;
        bytes[31] &= 0b01111111;

        // reverse because BigInt is Big-Endian while the field element is Little-Endian
        bytes.reverse();
        let y = BigInt::from_bytes(&bytes);
        let x = xrecover(&y, is_odd);
        Some(PointCoords { x, y })
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        GenericArray::from(self.ge.compress().0)
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        self.serialize_compressed()
    }

    fn deserialize(bytes: &[u8]) -> Result<Ed25519Point, DeserializationError> {
        let bytes_len = bytes.len();
        let mut edwards_y = CompressedEdwardsY([0; 32]);
        if bytes_len >= 32 {
            edwards_y.0.copy_from_slice(&bytes[..32]);
        } else {
            edwards_y.0[32 - bytes_len..].copy_from_slice(bytes);
        }
        let ge = edwards_y.decompress().ok_or(DeserializationError)?;
        Ok(Ed25519Point {
            purpose: "deserialize",
            ge,
        })
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> Ed25519Point {
        Ed25519Point {
            purpose: "scalar_mul",
            ge: self.ge * *fe.fe,
        }
    }

    fn generator_mul(scalar: &Self::Scalar) -> Self {
        Self {
            purpose: "generator_mul",
            ge: constants::ED25519_BASEPOINT_TABLE.basepoint_mul(&scalar.fe), // Much faster than multiplying manually by the generator point.
        }
    }

    fn add_point(&self, other: &Self) -> Ed25519Point {
        Ed25519Point {
            purpose: "add",
            ge: self.ge + other.ge,
        }
    }

    fn sub_point(&self, other: &Self) -> Ed25519Point {
        Ed25519Point {
            purpose: "sub",
            ge: self.ge - other.ge,
        }
    }

    fn neg_point(&self) -> Self {
        Ed25519Point {
            purpose: "neg_point",
            ge: -self.ge,
        }
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> Ed25519Point {
        Ed25519Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

#[allow(clippy::many_single_char_names)]
//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
fn xrecover(y_coor: &BigInt, is_odd: bool) -> BigInt {
    //   let d = "37095705934669439343138083508754565189542113879843219016388785533085940283555";
    //   let d_bn = BigInt::from(d.as_bytes());
    let q = BigInt::from(2u32).pow(255u32) - BigInt::from(19u32);
    let one = BigInt::one();
    let d_n = -BigInt::from(121_665i32);
    let d_d = expmod(&BigInt::from(121_666), &(q.clone() - BigInt::from(2)), &q);

    let d_bn = d_n * d_d;
    let y_sqr = y_coor * y_coor;
    let u = y_sqr.clone() - one.clone();
    let v = y_sqr * d_bn + one;
    let v_inv = expmod(&v, &(q.clone() - BigInt::from(2)), &q);

    let x_sqr = u * v_inv;
    let q_plus_3_div_8 = (q.clone() + BigInt::from(3i32)) / BigInt::from(8i32);

    let mut x = expmod(&x_sqr, &q_plus_3_div_8, &q);
    if BigInt::mod_sub(&(x.clone() * x.clone()), &x_sqr, &q) != BigInt::zero() {
        let q_minus_1_div_4 = (q.clone() - BigInt::from(1i32)) / BigInt::from(4i32);
        let i = expmod(&BigInt::from(2i32), &q_minus_1_div_4, &q);
        x = BigInt::mod_mul(&x, &i, &q);
    }
    if x.is_odd() != is_odd {
        q - x
    } else {
        x
    }
}

//helper function, based on https://ed25519.cr.yp.to/python/ed25519.py
fn expmod(b: &BigInt, e: &BigInt, m: &BigInt) -> BigInt {
    let one = BigInt::one();
    if e.clone() == BigInt::zero() {
        return one;
    };
    let t_temp = expmod(b, &(e.clone() / BigInt::from(2u32)), m);
    let mut t = BigInt::mod_pow(&t_temp, &BigInt::from(2u32), m);

    if BigInt::modulus(e, &BigInt::from(2)) != BigInt::zero() {
        t = BigInt::mod_mul(&t, b, m);
    }
    t
}

#[cfg(test)]
mod tests {
    use crate::arithmetic::traits::Converter;
    use crate::elliptic::curves::{Ed25519, Point, Scalar};
    use crate::BigInt;

    #[test]
    fn test_vectors_coordinates() {
        // These coordinates were generated in dalek-curve25519 using the following code:
        //     let mut p = super::constants::ED25519_BASEPOINT_POINT;
        //     for _ in 0..15 {
        //         let recip = p.Z.invert();
        //         let x = &p.X * &recip;
        //         let y = &p.Y * &recip;
        //         println!("({:?}, {:?}),", x.to_bytes(), y.to_bytes());
        //         p = p.double();
        //     }
        #[rustfmt::skip]
            let dalek = [
            ([26, 213, 37, 143, 96, 45, 86, 201, 178, 167, 37, 149, 96, 199, 44, 105, 92, 220, 214, 253, 49, 226, 164, 192, 254, 83, 110, 205, 211, 54, 105, 33], [88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102]),
            ([14, 206, 67, 40, 78, 161, 197, 131, 95, 164, 215, 21, 69, 142, 13, 8, 172, 231, 51, 24, 125, 59, 4, 61, 108, 4, 90, 159, 76, 56, 171, 54], [201, 163, 248, 106, 174, 70, 95, 14, 86, 81, 56, 100, 81, 15, 57, 151, 86, 31, 162, 201, 232, 94, 162, 29, 194, 41, 35, 9, 243, 205, 96, 34]),
            ([112, 248, 201, 196, 87, 166, 58, 73, 71, 21, 206, 147, 193, 158, 115, 26, 249, 32, 53, 122, 184, 212, 37, 131, 70, 241, 207, 86, 219, 168, 61, 32], [47, 17, 50, 202, 97, 171, 56, 223, 240, 15, 47, 234, 50, 40, 242, 76, 108, 113, 213, 128, 133, 184, 14, 71, 225, 149, 21, 203, 39, 232, 208, 71]),
            ([200, 132, 165, 8, 188, 253, 135, 59, 153, 139, 105, 128, 123, 198, 58, 235, 147, 207, 78, 248, 92, 45, 134, 66, 182, 113, 215, 151, 95, 225, 66, 103], [180, 185, 55, 252, 169, 91, 47, 30, 147, 228, 30, 98, 252, 60, 120, 129, 143, 243, 138, 102, 9, 111, 173, 110, 121, 115, 229, 201, 0, 6, 211, 33]),
            ([248, 249, 40, 108, 109, 89, 178, 89, 116, 35, 191, 231, 51, 141, 87, 9, 145, 156, 36, 8, 21, 43, 226, 184, 238, 58, 229, 39, 6, 134, 164, 35], [235, 39, 103, 193, 55, 171, 122, 216, 39, 156, 7, 142, 255, 17, 106, 176, 120, 110, 173, 58, 46, 15, 152, 159, 114, 195, 127, 130, 242, 150, 150, 112]),
            ([38, 79, 126, 151, 246, 64, 221, 79, 252, 82, 120, 249, 144, 49, 3, 230, 125, 86, 57, 11, 29, 86, 130, 133, 249, 26, 66, 23, 105, 108, 207, 57], [105, 210, 6, 58, 79, 57, 45, 249, 56, 64, 140, 76, 231, 5, 18, 180, 120, 139, 248, 192, 236, 147, 222, 122, 107, 206, 44, 225, 14, 169, 52, 68]),
            ([11, 164, 60, 176, 15, 122, 81, 241, 120, 214, 217, 106, 253, 70, 232, 184, 168, 121, 29, 135, 249, 144, 242, 156, 19, 41, 248, 11, 32, 100, 250, 5], [38, 9, 218, 23, 175, 149, 214, 251, 106, 25, 13, 110, 94, 18, 241, 153, 76, 170, 168, 111, 121, 134, 244, 114, 40, 0, 38, 249, 234, 158, 25, 61]),
            ([135, 221, 207, 240, 91, 73, 162, 93, 64, 122, 35, 38, 164, 122, 131, 138, 183, 139, 210, 26, 191, 234, 2, 36, 8, 95, 123, 169, 177, 190, 157, 55], [252, 134, 75, 8, 238, 231, 160, 253, 33, 69, 9, 52, 193, 97, 50, 35, 252, 155, 85, 72, 83, 153, 247, 99, 208, 153, 206, 1, 224, 159, 235, 40]),
            ([86, 165, 194, 12, 221, 188, 184, 32, 109, 87, 97, 181, 251, 120, 181, 212, 73, 84, 144, 38, 193, 203, 233, 230, 191, 236, 29, 78, 237, 7, 126, 94], [199, 246, 108, 86, 49, 32, 20, 14, 168, 217, 39, 193, 154, 61, 27, 125, 14, 38, 211, 129, 170, 235, 245, 107, 121, 2, 241, 81, 92, 117, 85, 15]),
            ([10, 52, 205, 130, 60, 51, 9, 84, 210, 97, 57, 48, 155, 253, 239, 33, 38, 212, 112, 250, 238, 249, 49, 51, 115, 132, 208, 179, 129, 191, 236, 46], [232, 147, 139, 0, 100, 247, 156, 184, 116, 224, 230, 73, 72, 77, 77, 72, 182, 25, 161, 64, 183, 217, 50, 65, 124, 130, 55, 161, 45, 220, 210, 84]),
            ([104, 43, 74, 91, 213, 199, 81, 145, 29, 225, 42, 75, 196, 71, 241, 188, 122, 179, 203, 200, 182, 124, 172, 144, 5, 253, 243, 249, 82, 58, 17, 107], [61, 193, 39, 243, 89, 67, 149, 144, 197, 150, 121, 245, 244, 149, 101, 41, 6, 156, 81, 5, 24, 218, 184, 46, 121, 126, 105, 89, 113, 1, 235, 26]),
            ([247, 23, 19, 189, 251, 188, 210, 236, 69, 179, 21, 49, 233, 175, 130, 132, 61, 40, 198, 252, 17, 245, 65, 181, 139, 211, 18, 118, 82, 231, 26, 60], [78, 54, 17, 7, 162, 21, 32, 81, 196, 42, 195, 98, 139, 94, 127, 166, 15, 249, 69, 133, 108, 17, 134, 183, 126, 229, 215, 249, 195, 145, 28, 5]),
            ([234, 214, 222, 41, 58, 0, 185, 2, 89, 203, 38, 196, 186, 153, 177, 151, 47, 142, 0, 146, 38, 79, 82, 235, 71, 27, 137, 139, 36, 192, 19, 125], [213, 32, 91, 128, 166, 128, 32, 149, 195, 233, 159, 142, 135, 158, 30, 158, 122, 199, 204, 117, 108, 165, 241, 145, 26, 168, 1, 44, 171, 118, 169, 89]),
            ([222, 201, 177, 49, 16, 22, 170, 53, 20, 106, 212, 181, 52, 130, 113, 210, 74, 93, 154, 31, 83, 38, 60, 229, 142, 141, 51, 127, 255, 169, 213, 23], [137, 175, 246, 164, 100, 213, 16, 224, 29, 173, 239, 68, 189, 218, 131, 172, 122, 168, 240, 28, 7, 249, 195, 67, 108, 63, 183, 211, 135, 34, 2, 115]),
            ([138, 75, 231, 56, 188, 218, 194, 176, 133, 225, 74, 254, 45, 68, 132, 203, 32, 107, 45, 191, 17, 156, 215, 190, 211, 62, 95, 191, 104, 188, 168, 7], [1, 137, 40, 34, 106, 120, 170, 41, 3, 200, 116, 149, 3, 62, 220, 189, 7, 19, 168, 162, 32, 45, 179, 24, 112, 66, 253, 122, 196, 215, 73, 114]),
        ];

        let mut p = Point::<Ed25519>::generator().to_point();
        for (mut x, mut y) in dalek {
            // coordinates are in little endian, but BigInt uses Big Endian.
            x.reverse();
            y.reverse();
            let x_big = BigInt::from_bytes(&x);
            let y_big = BigInt::from_bytes(&y);
            let coordinates = p.coords().unwrap();
            assert_eq!(coordinates.y, y_big);
            assert_eq!(coordinates.x, x_big);
            p = p * Scalar::from(2u16);
        }
    }
}
