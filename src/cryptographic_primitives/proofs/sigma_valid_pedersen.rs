/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use crate::cryptographic_primitives::commitments::traits::Commitment;
use crate::cryptographic_primitives::hashing::{Digest, DigestExt};
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::marker::HashChoice;

use super::ProofError;

/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (m,r) such that c = mG + rH.
/// witness: (m,r), statement: c, The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A1 = s1*G , A2 = s2*H for random s1,s2
/// prover calculates challenge e = H(G,H,c,A1,A2)
/// prover calculates z1  = s1 + em, z2 = s2 + er
/// prover sends pi = {e, A1,A2,c, z1,z2}
///
/// verifier checks that z1*G + z2*H  = A1 + A2 + ec
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PedersenProof<E: Curve, H: Digest + Clone> {
    e: Scalar<E>,
    a1: Point<E>,
    a2: Point<E>,
    pub com: Point<E>,
    z1: Scalar<E>,
    z2: Scalar<E>,
    #[serde(skip)]
    hash_choice: HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> PedersenProof<E, H> {
    #[allow(clippy::many_single_char_names)]
    pub fn prove(m: &Scalar<E>, r: &Scalar<E>) -> PedersenProof<E, H> {
        let g = Point::<E>::generator();
        let h = Point::<E>::base_point2();
        let s1 = Scalar::random();
        let s2 = Scalar::random();
        let a1 = g * &s1;
        let a2 = h * &s2;
        let com: Point<E> = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_bigint(),
            &r.to_bigint(),
        );

        let e = H::new()
            .chain_points([&g.to_point(), h, &com, &a1, &a2])
            .result_scalar();

        let em = &e * m;
        let z1 = &s1 + em;
        let er = &e * r;
        let z2 = &s2 + er;

        PedersenProof {
            e,
            a1,
            a2,
            com,
            z1,
            z2,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &PedersenProof<E, H>) -> Result<(), ProofError> {
        let g = Point::<E>::generator();
        let h = Point::<E>::base_point2();

        let e = H::new()
            .chain_points([&g.to_point(), h, &proof.com, &proof.a1, &proof.a2])
            .result_scalar();

        let z1g = g * &proof.z1;
        let z2h = h * &proof.z2;
        let lhs = &z1g + &z2h;
        let rhs = &proof.a1 + &proof.a2;
        let ecom = &proof.com * &e;
        let rhs = rhs + &ecom;

        if lhs == rhs {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves_and_hashes!(test_pedersen_proof);
    fn test_pedersen_proof<E: Curve, H: Digest + Clone>() {
        let m = Scalar::random();
        let r = Scalar::random();
        let pedersen_proof = PedersenProof::<E, H>::prove(&m, &r);
        PedersenProof::verify(&pedersen_proof).expect("error pedersen");
    }
}
