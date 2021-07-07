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
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalProof<E: Curve> {
    pub T: PointZ<E>,
    pub A3: PointZ<E>,
    pub z1: ScalarZ<E>,
    pub z2: ScalarZ<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalWitness<E: Curve> {
    pub r: ScalarZ<E>,
    pub x: ScalarZ<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalStatement<E: Curve> {
    pub G: Point<E>,
    pub H: Point<E>,
    pub Y: Point<E>,
    pub D: PointZ<E>,
    pub E: PointZ<E>,
}

impl<E: Curve> HomoELGamalProof<E> {
    pub fn prove(
        w: &HomoElGamalWitness<E>,
        delta: &HomoElGamalStatement<E>,
    ) -> HomoELGamalProof<E> {
        let s1: Scalar<E> = Scalar::random();
        let s2: Scalar<E> = Scalar::random();
        let A1 = &delta.H * &s1;
        let A2 = &delta.Y * &s2;
        let A3 = &delta.G * &s2;
        let T = A1 + A2;
        let e = HSha256::create_hash_from_ge_z(&[
            &T,
            &A3,
            &PointZ::from(delta.G.clone()),
            &PointZ::from(delta.H.clone()),
            &PointZ::from(delta.Y.clone()),
            &PointZ::from(delta.D.clone()),
            &PointZ::from(delta.E.clone()),
        ]);
        // dealing with zero field element
        let z1 = if !w.x.is_zero() {
            &s1 + &w.x * &e
        } else {
            ScalarZ::from(s1)
        };
        let z2 = s2 + &w.r * e;
        HomoELGamalProof { T, A3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement<E>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge_z(&[
            &self.T,
            &self.A3,
            &PointZ::from(delta.G.clone()),
            &PointZ::from(delta.H.clone()),
            &PointZ::from(delta.Y.clone()),
            &PointZ::from(delta.D.clone()),
            &PointZ::from(delta.E.clone()),
        ]);
        let z1H_plus_z2Y = &delta.H * &self.z1 + &delta.Y * &self.z2;
        let T_plus_eD = &self.T + &delta.D * &e;
        let z2G = &delta.G * &self.z2;
        let A3_plus_eE = &self.A3 + &delta.E * &e;
        if z1H_plus_z2Y == T_plus_eD && z2G == A3_plus_eE {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_for_all_curves;

    test_for_all_curves!(test_correct_general_homo_elgamal);
    fn test_correct_general_homo_elgamal<E: Curve>() {
        let witness = HomoElGamalWitness::<E> {
            r: ScalarZ::random(),
            x: ScalarZ::random(),
        };
        let G = Point::<E>::generator();
        let h = Scalar::random();
        let H = G * h;
        let y = Scalar::random();
        let Y = G * y;
        let D = &H * &witness.x + &Y * &witness.r;
        let E = G * &witness.r;
        let delta = HomoElGamalStatement {
            G: G.to_point(),
            H,
            Y,
            D,
            E,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<E: Curve>() {
        let witness = HomoElGamalWitness {
            r: ScalarZ::random(),
            x: ScalarZ::random(),
        };
        let G = Point::<E>::generator();
        let y = Scalar::random();
        let Y = G * y;
        let D = G * &witness.x + &Y * &witness.r;
        let E = G * &witness.r;
        let delta = HomoElGamalStatement {
            G: G.to_point(),
            H: G.to_point(),
            Y,
            D,
            E,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves!(test_wrong_homo_elgamal);
    fn test_wrong_homo_elgamal<E: Curve>() {
        // test for E = (r+1)G
        let witness = HomoElGamalWitness::<E> {
            r: ScalarZ::random(),
            x: ScalarZ::random(),
        };
        let G = Point::<E>::generator();
        let h = Scalar::random();
        let H = G * h;
        let y = Scalar::random();
        let Y = G * y;
        let D = &H * &witness.x + &Y * &witness.r;
        let E = G * &witness.r + G;
        let delta = HomoElGamalStatement {
            G: G.to_point(),
            H,
            Y,
            D,
            E,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
