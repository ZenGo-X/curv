#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use digest::Digest;
use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::hashing::DigestExt;
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::marker::HashChoice;

use super::ProofError;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
///
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoELGamalProof<E: Curve, H: Digest + Clone> {
    pub T: Point<E>,
    pub A3: Point<E>,
    pub z1: Scalar<E>,
    pub z2: Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoElGamalWitness<E: Curve> {
    pub r: Scalar<E>,
    pub x: Scalar<E>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HomoElGamalStatement<E: Curve> {
    pub G: Point<E>,
    pub H: Point<E>,
    pub Y: Point<E>,
    pub D: Point<E>,
    pub E: Point<E>,
}

impl<E: Curve, H: Digest + Clone> HomoELGamalProof<E, H> {
    pub fn prove(
        w: &HomoElGamalWitness<E>,
        delta: &HomoElGamalStatement<E>,
    ) -> HomoELGamalProof<E, H> {
        let s1: Scalar<E> = Scalar::random();
        let s2: Scalar<E> = Scalar::random();
        let A1 = &delta.H * &s1;
        let A2 = &delta.Y * &s2;
        let A3 = &delta.G * &s2;
        let T = A1 + A2;
        let e = H::new()
            .chain_point(&T)
            .chain_point(&A3)
            .chain_point(&delta.G)
            .chain_point(&delta.H)
            .chain_point(&delta.Y)
            .chain_point(&delta.D)
            .chain_point(&delta.E)
            .result_scalar();
        // dealing with zero field element
        let z1 = &s1 + &w.x * &e;
        let z2 = s2 + &w.r * e;
        HomoELGamalProof {
            T,
            A3,
            z1,
            z2,
            hash_choice: HashChoice::new(),
        }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement<E>) -> Result<(), ProofError> {
        let e = H::new()
            .chain_point(&self.T)
            .chain_point(&self.A3)
            .chain_point(&delta.G)
            .chain_point(&delta.H)
            .chain_point(&delta.Y)
            .chain_point(&delta.D)
            .chain_point(&delta.E)
            .result_scalar();
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
    use crate::test_for_all_curves_and_hashes;

    test_for_all_curves_and_hashes!(test_correct_general_homo_elgamal);
    fn test_correct_general_homo_elgamal<E: Curve, H: Digest + Clone>() {
        let witness = HomoElGamalWitness {
            r: Scalar::random(),
            x: Scalar::random(),
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
        let proof = HomoELGamalProof::<E, H>::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves_and_hashes!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<E: Curve, H: Digest + Clone>() {
        let witness = HomoElGamalWitness {
            r: Scalar::random(),
            x: Scalar::random(),
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
        let proof = HomoELGamalProof::<E, H>::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves_and_hashes!(test_wrong_homo_elgamal);
    fn test_wrong_homo_elgamal<E: Curve, H: Digest + Clone>() {
        // test for E = (r+1)G
        let witness = HomoElGamalWitness {
            r: Scalar::random(),
            x: Scalar::random(),
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
        let proof = HomoELGamalProof::<E, H>::prove(&witness, &delta);
        assert!(!proof.verify(&delta).is_ok());
    }
}
