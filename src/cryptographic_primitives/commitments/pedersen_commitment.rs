/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use std::marker::PhantomData;

use super::traits::Commitment;
use super::SECURITY_BITS;
use crate::arithmetic::traits::*;

use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::BigInt;

/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
///
pub struct PedersenCommitment<E: Curve>(PhantomData<E>);

impl<E: Curve> Commitment<Point<E>> for PedersenCommitment<E> {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> Point<E> {
        let g = Point::generator();
        let h = Point::base_point2();
        let message_scalar: Scalar<E> = Scalar::from(message);
        let blinding_scalar: Scalar<E> = Scalar::from(blinding_factor);
        let mg = g * message_scalar;
        let rh = h * blinding_scalar;
        mg + rh
    }

    fn create_commitment(message: &BigInt) -> (Point<E>, BigInt) {
        let blinding_factor = BigInt::sample(SECURITY_BITS);
        let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
            message,
            &blinding_factor,
        );
        (com, blinding_factor)
    }
}
