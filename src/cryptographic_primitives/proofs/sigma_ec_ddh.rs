/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};

use super::ProofError;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::{Curve, Point, Scalar, ScalarZ};

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
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ECDDHProof<E: Curve> {
    pub a1: Point<E>,
    pub a2: Point<E>,
    pub z: ScalarZ<E>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement<E: Curve> {
    pub g1: Point<E>,
    pub h1: Point<E>,
    pub g2: Point<E>,
    pub h2: Point<E>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness<E: Curve> {
    pub x: Scalar<E>,
}

impl<E: Curve> ECDDHProof<E> {
    pub fn prove(w: &ECDDHWitness<E>, delta: &ECDDHStatement<E>) -> ECDDHProof<E> {
        let s = Scalar::random();
        let a1 = &delta.g1 * &s;
        let a2 = &delta.g2 * &s;
        let e =
            HSha256::create_hash_from_ge(&[&delta.g1, &delta.h1, &delta.g2, &delta.h2, &a1, &a2]);
        let z = &s + e * &w.x;
        ECDDHProof { a1, a2, z }
    }

    pub fn verify(&self, delta: &ECDDHStatement<E>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &delta.g1, &delta.h1, &delta.g2, &delta.h2, &self.a1, &self.a2,
        ]);
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
    use crate::test_for_all_curves;

    use super::*;

    test_for_all_curves!(test_ecddh_proof);
    fn test_ecddh_proof<E: Curve>() {
        let x = Scalar::<E>::random();
        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let h1 = g1 * &x;
        let h2 = g2 * &x;
        let delta = ECDDHStatement {
            g1: g1.to_point(),
            g2: g2.to_point(),
            h1,
            h2,
        };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves!(test_wrong_ecddh_proof);
    fn test_wrong_ecddh_proof<E: Curve>() {
        let x = Scalar::<E>::random();
        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let x2 = Scalar::<E>::random();
        let h1 = g1 * &x;
        let h2 = g2 * &x2;
        let delta = ECDDHStatement {
            g1: g1.to_point(),
            g2: g2.to_point(),
            h1,
            h2,
        };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
