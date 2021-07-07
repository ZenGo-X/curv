#![allow(non_snake_case)]
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
use crate::elliptic::curves::{Curve, Point, PointZ, Scalar, ScalarZ};

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, Q, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG, Q = xG
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalDlogProof<E: Curve> {
    pub A1: PointZ<E>,
    pub A2: PointZ<E>,
    pub A3: PointZ<E>,
    pub z1: ScalarZ<E>,
    pub z2: ScalarZ<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogWitness<E: Curve> {
    pub r: Scalar<E>,
    pub x: Scalar<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogStatement<E: Curve> {
    pub G: Point<E>,
    pub Y: Point<E>,
    pub Q: Point<E>,
    pub D: PointZ<E>,
    pub E: Point<E>,
}

impl<E: Curve> HomoELGamalDlogProof<E> {
    pub fn prove(
        w: &HomoElGamalDlogWitness<E>,
        delta: &HomoElGamalDlogStatement<E>,
    ) -> HomoELGamalDlogProof<E> {
        let s1 = Scalar::<E>::random();
        let s2 = Scalar::<E>::random();
        let A1 = &delta.G * &s1;
        let A2 = &delta.Y * &s2;
        let A3 = &delta.G * &s2;
        let e = HSha256::create_hash_from_ge_z(&[
            &A1,
            &A2,
            &A3,
            &PointZ::from(delta.G.clone()),
            &PointZ::from(delta.Y.clone()),
            &delta.D,
            &PointZ::from(delta.E.clone()),
        ]);
        let z1 = &s1 + &e * &w.x;
        let z2 = &s2 + e * &w.r;
        HomoELGamalDlogProof { A1, A2, A3, z1, z2 }
    }

    pub fn verify(&self, delta: &HomoElGamalDlogStatement<E>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge_z(&[
            &self.A1,
            &self.A2,
            &self.A3,
            &PointZ::from(delta.G.clone()),
            &PointZ::from(delta.Y.clone()),
            &delta.D,
            &PointZ::from(delta.E.clone()),
        ]);
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
    use crate::test_for_all_curves;

    use super::*;

    test_for_all_curves!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<E: Curve>() {
        let witness = HomoElGamalDlogWitness::<E> {
            r: Scalar::random(),
            x: Scalar::random(),
        };
        let G = Point::<E>::generator();
        let Y = G * Scalar::random();
        let D = G * &witness.x + &Y * &witness.r;
        let E = G * &witness.r;
        let Q = G * &witness.x;
        let delta = HomoElGamalDlogStatement {
            G: G.to_point_owned(),
            Y,
            Q,
            D,
            E,
        };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    // TODO: add more fail scenarios
    test_for_all_curves!(test_wrong_homo_elgamal);
    fn test_wrong_homo_elgamal<E: Curve>() {
        // test for Q = (x+1)G
        let witness = HomoElGamalDlogWitness::<E> {
            r: Scalar::random(),
            x: Scalar::random(),
        };
        let G = Point::<E>::generator();
        let Y = G * Scalar::random();
        let D = G * &witness.x + &Y * &witness.r;
        let E = (G * &witness.r + G).ensure_nonzero().unwrap();
        let Q = (G * &witness.x + G).ensure_nonzero().unwrap();
        let delta = HomoElGamalDlogStatement {
            G: G.to_point_owned(),
            Y,
            Q,
            D,
            E,
        };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
