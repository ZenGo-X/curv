/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

use super::traits::Commitment;
use elliptic::curves::secp256_k1::Secp256k1Point;
use elliptic::curves::secp256_k1::Secp256k1Scalar;
use elliptic::curves::traits::*;

use BigInt;

pub struct PedersenCommitment;

impl Commitment<Secp256k1Point> for PedersenCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> Secp256k1Point {
        let g: Secp256k1Point = ECPoint::new();
        let h = Secp256k1Point::base_point2();
        let message_scalar: Secp256k1Scalar = ECScalar::from_big_int(message);
        let blinding_scalar: Secp256k1Scalar = ECScalar::from_big_int(blinding_factor);
        let mg = g.scalar_mul(&message_scalar.get_element());
        let rh = h.scalar_mul(&blinding_scalar.get_element());
        mg.add_point(&rh.get_element())
    }

    fn create_commitment(message: &BigInt) -> (Secp256k1Point, BigInt) {
        let g: Secp256k1Point = ECPoint::new();
        let h = Secp256k1Point::base_point2();
        let message_scalar: Secp256k1Scalar = ECScalar::from_big_int(message);
        let blinding_scalar: Secp256k1Scalar = ECScalar::new_random();
        let mg = g.scalar_mul(&message_scalar.get_element());
        let rh = h.scalar_mul(&blinding_scalar.get_element());
        (
            mg.add_point(&rh.get_element()),
            blinding_scalar.to_big_int(),
        )
    }
}
