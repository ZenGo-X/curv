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
/// proof of knowledge of (r) such that c = mG + rH.
/// witness: (r), statement: (c,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A = s*H for random s
/// prover calculates challenge e = H(G,H,c,A,m)
/// prover calculates z  = s + er,
/// prover sends pi = {e, m,A,c, z}
/// verifier checks that emG + zH  = A + ec
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PedersenBlindingProof<E: Curve, H: Digest + Clone> {
    e: Scalar<E>,
    pub m: Scalar<E>,
    a: Point<E>,
    pub com: Point<E>,
    z: Scalar<E>,
    #[serde(skip)]
    hash_choice: HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> PedersenBlindingProof<E, H> {
    #[allow(clippy::many_single_char_names)]
    //TODO: add self verification to prover proof
    pub fn prove(m: &Scalar<E>, r: &Scalar<E>) -> PedersenBlindingProof<E, H> {
        let h = Point::<E>::base_point2();
        let s = Scalar::<E>::random();
        let a = h * &s;
        let com: Point<E> = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_bigint(),
            &r.to_bigint(),
        );
        let g = Point::<E>::generator();
        let e = H::new()
            .chain_points([g.as_point(), h, &com, &a])
            .chain_scalar(m)
            .result_scalar();

        let er = &e * r;
        let z = &s + &er;
        PedersenBlindingProof {
            e,
            m: m.clone(),
            a,
            com,
            z,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &PedersenBlindingProof<E, H>) -> Result<(), ProofError> {
        let g = Point::<E>::generator();
        let h = Point::<E>::base_point2();
        let e = H::new()
            .chain_points([g.as_point(), h, &proof.com, &proof.a])
            .chain_scalar(&proof.m)
            .result_scalar();

        let zh = h * &proof.z;
        let mg = g * &proof.m;
        let emg = mg * &e;
        let lhs = zh + emg;
        let ecom = &proof.com * &e;
        let rhs = ecom + &proof.a;

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

    crate::test_for_all_curves_and_hashes!(test_pedersen_blind_proof);
    fn test_pedersen_blind_proof<E: Curve, H: Digest + Clone>() {
        let m = Scalar::random();
        let r = Scalar::random();
        let pedersen_proof = PedersenBlindingProof::<E, H>::prove(&m, &r);
        PedersenBlindingProof::verify(&pedersen_proof).expect("error pedersen blind");
    }
}
