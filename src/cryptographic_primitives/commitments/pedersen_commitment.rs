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
use super::SECURITY_BITS;
use arithmetic::traits::Samplable;
use elliptic::curves::secp256_k1::Secp256k1Point;
use elliptic::curves::secp256_k1::Secp256k1Scalar;
use elliptic::curves::traits::*;
use BigInt;

#[cfg(feature = "curvesecp256k1")]
pub struct PedersenCommitment;
#[cfg(feature = "curvesecp256k1")]
impl Commitment<Secp256k1Point> for PedersenCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> Secp256k1Point {
        let g: Secp256k1Point = ECPoint::generator();
        let h = Secp256k1Point::base_point2();
        let message_scalar: Secp256k1Scalar = ECScalar::from(message);
        let blinding_scalar: Secp256k1Scalar = ECScalar::from(blinding_factor);
        let mg = g * message_scalar;
        let rh = h * blinding_scalar;
        mg + rh
    }

    fn create_commitment(message: &BigInt) -> (Secp256k1Point, BigInt) {
        let blinding_factor = BigInt::sample(SECURITY_BITS);
        let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
            message,
            &blinding_factor,
        );
        (com, blinding_factor)
    }
}
