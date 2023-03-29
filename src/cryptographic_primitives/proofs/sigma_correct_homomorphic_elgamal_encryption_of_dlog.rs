#![allow(non_snake_case)]
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

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, Q, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG, Q = xG
///
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoELGamalDlogProof<E: Curve, H: Digest + Clone> {
    pub A1: Point<E>,
    pub A2: Point<E>,
    pub A3: Point<E>,
    pub z1: Scalar<E>,
    pub z2: Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoElGamalDlogWitness<E: Curve> {
    pub r: Scalar<E>,
    pub x: Scalar<E>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoElGamalDlogStatement<E: Curve> {
    pub G: Point<E>,
    pub Y: Point<E>,
    pub Q: Point<E>,
    pub D: Point<E>,
    pub E: Point<E>,
}

impl<E: Curve, H: Digest + Clone> HomoELGamalDlogProof<E, H> {
    pub fn prove(
        w: &HomoElGamalDlogWitness<E>,
        delta: &HomoElGamalDlogStatement<E>,
    ) -> HomoELGamalDlogProof<E, H> {
        let s1 = Scalar::<E>::random();
        let s2 = Scalar::<E>::random();
        let A1 = &delta.G * &s1;
        let A2 = &delta.Y * &s2;
        let A3 = &delta.G * &s2;
        let e = H::new()
            .chain_points([&A1, &A2, &A3, &delta.G, &delta.Y, &delta.D, &delta.E])
            .result_scalar();
        let z1 = &s1 + &e * &w.x;
        let z2 = &s2 + e * &w.r;
        HomoELGamalDlogProof {
            A1,
            A2,
            A3,
            z1,
            z2,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(&self, delta: &HomoElGamalDlogStatement<E>) -> Result<(), ProofError> {
        let e = H::new()
            .chain_points([
                &self.A1, &self.A2, &self.A3, &delta.G, &delta.Y, &delta.D, &delta.E,
            ])
            .result_scalar();
        let z1G = &delta.G * &self.z1;
        let z2Y = &delta.Y * &self.z2;
        let z2G = &delta.G * &self.z2;
        let A1_plus_eQ = &self.A1 + &delta.Q * &e;
        let A3_plus_eE = &self.A3 + &delta.E * &e;
        let D_minus_Q = &delta.D - &delta.Q;
        let A2_plus_eDmQ = self.A2.clone() + D_minus_Q * e;
        if z1G == A1_plus_eQ && z2G == A3_plus_eE && z2Y == A2_plus_eDmQ {
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

    test_for_all_curves_and_hashes!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<E: Curve, H: Digest + Clone>() {
        let witness = HomoElGamalDlogWitness {
            r: Scalar::random(),
            x: Scalar::random(),
        };
        let G = Point::<E>::generator();
        let Y = G * Scalar::random();
        let D = G * &witness.x + &Y * &witness.r;
        let E = G * &witness.r;
        let Q = G * &witness.x;
        let delta = HomoElGamalDlogStatement {
            G: G.to_point(),
            Y,
            Q,
            D,
            E,
        };
        let proof = HomoELGamalDlogProof::<E, H>::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    // TODO: add more fail scenarios
    test_for_all_curves_and_hashes!(test_wrong_homo_elgamal);
    fn test_wrong_homo_elgamal<E: Curve, H: Digest + Clone>() {
        // test for Q = (x+1)G
        let witness = HomoElGamalDlogWitness {
            r: Scalar::random(),
            x: Scalar::random(),
        };
        let G = Point::<E>::generator();
        let Y = G * Scalar::random();
        let D = G * &witness.x + &Y * &witness.r;
        let E = G * &witness.r + G;
        let Q = G * &witness.x + G;
        let delta = HomoElGamalDlogStatement {
            G: G.to_point(),
            Y,
            Q,
            D,
            E,
        };
        let proof = HomoELGamalDlogProof::<E, H>::prove(&witness, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
