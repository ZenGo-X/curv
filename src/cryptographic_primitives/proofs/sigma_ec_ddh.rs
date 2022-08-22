/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::hashing::{Digest, DigestExt};
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::marker::HashChoice;

use super::ProofError;

/// This protocol is the elliptic curve form of the protocol from :
///  D. Chaum, T. P. Pedersen. Transferred cash grows in size. In Advances in Cryptology, EUROCRYPT , volume 658 of Lecture Notes in Computer Science, pages 390 - 407, 1993.
///  This is a proof of membership of DDH: (G, xG, yG, xyG)
/// The statement is (G1,H1, G2, H2), the witness is x. The relation outputs 1 if :
/// H1 = xG1, H2 = xG2
/// The protocol:
/// 1: Prover chooses A1 = s*G1 , A2 = sG2  for random s1,s2
/// prover calculates challenge e = H(G1,H1,G2,H2,A1,A2)
/// prover calculates z  = s + ex,
/// prover sends pi = {e, A1,A2,z}
///
/// verifier checks that zG1 = A1 + eH1, zG2 = A2 + eH2
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ECDDHProof<E: Curve, H: Digest + Clone> {
    pub a1: Point<E>,
    pub a2: Point<E>,
    pub z: Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ECDDHStatement<E: Curve> {
    pub g1: Point<E>,
    pub h1: Point<E>,
    pub g2: Point<E>,
    pub h2: Point<E>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ECDDHWitness<E: Curve> {
    pub x: Scalar<E>,
}

impl<E: Curve, H: Digest + Clone> ECDDHProof<E, H> {
    pub fn prove(w: &ECDDHWitness<E>, delta: &ECDDHStatement<E>) -> ECDDHProof<E, H> {
        let s = Scalar::random();
        let a1 = &delta.g1 * &s;
        let a2 = &delta.g2 * &s;
        let e = H::new()
            .chain_point(&delta.g1)
            .chain_point(&delta.h1)
            .chain_point(&delta.g2)
            .chain_point(&delta.h2)
            .chain_point(&a1)
            .chain_point(&a2)
            .result_scalar();
        let z = &s + e * &w.x;
        ECDDHProof {
            a1,
            a2,
            z,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(&self, delta: &ECDDHStatement<E>) -> Result<(), ProofError> {
        let e = H::new()
            .chain_point(&delta.g1)
            .chain_point(&delta.h1)
            .chain_point(&delta.g2)
            .chain_point(&delta.h2)
            .chain_point(&self.a1)
            .chain_point(&self.a2)
            .result_scalar();
        let z_g1 = &delta.g1 * &self.z;
        let z_g2 = &delta.g2 * &self.z;
        let a1_plus_e_h1 = &self.a1 + &delta.h1 * &e;
        let a2_plus_e_h2 = &self.a2 + &delta.h2 * e;
        if z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2 {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_for_all_curves_and_hashes;

    use super::*;

    test_for_all_curves_and_hashes!(test_ecddh_proof);
    fn test_ecddh_proof<E: Curve, H: Digest + Clone>() {
        let x = Scalar::random();
        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let h1 = g1 * &x;
        let h2 = g2 * &x;
        let delta = ECDDHStatement {
            g1: g1.to_point(),
            g2: g2.clone(),
            h1,
            h2,
        };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::<E, H>::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves_and_hashes!(test_wrong_ecddh_proof);
    fn test_wrong_ecddh_proof<E: Curve, H: Digest + Clone>() {
        let x = Scalar::random();
        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let x2 = Scalar::random();
        let h1 = g1 * &x;
        let h2 = g2 * &x2;
        let delta = ECDDHStatement {
            g1: g1.to_point(),
            g2: g2.clone(),
            h1,
            h2,
        };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::<E, H>::prove(&w, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
