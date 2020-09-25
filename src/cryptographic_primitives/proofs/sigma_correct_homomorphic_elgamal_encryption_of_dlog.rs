#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::ProofError;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::traits::*;
use crate::FE;
use crate::GE;
use zeroize::Zeroize;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, Q, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG, Q = xG
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalDlogProof {
    pub A1: GE,
    pub A2: GE,
    pub A3: GE,
    pub z1: FE,
    pub z2: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogWitness {
    pub r: FE,
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogStatement {
    pub G: GE,
    pub Y: GE,
    pub Q: GE,
    pub D: GE,
    pub E: GE,
}

impl HomoELGamalDlogProof {
    pub fn prove(
        w: &HomoElGamalDlogWitness,
        delta: &HomoElGamalDlogStatement,
    ) -> HomoELGamalDlogProof {
        let mut s1: FE = ECScalar::new_random();
        let mut s2: FE = ECScalar::new_random();
        let A1 = delta.G * s1.clone();
        let A2 = delta.Y * s2.clone();
        let A3 = delta.G * s2.clone();
        let e =
            HSha256::create_hash_from_ge(&[&A1, &A2, &A3, &delta.G, &delta.Y, &delta.D, &delta.E]);
        let z1 = s1.clone() + e.clone() * w.x.clone();
        let z2 = s2.clone() + e.clone() * w.r.clone();
        s1.zeroize();
        s2.zeroize();
        HomoELGamalDlogProof { A1, A2, A3, z1, z2 }
    }

    pub fn verify(&self, delta: &HomoElGamalDlogStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.A1, &self.A2, &self.A3, &delta.G, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1G = delta.G * self.z1.clone();
        let z2Y = delta.Y * self.z2.clone();
        let z2G = delta.G * self.z2.clone();
        let A1_plus_eQ = self.A1 + delta.Q * e.clone();
        let A3_plus_eE = self.A3 + delta.E * e.clone();
        let D_minus_Q = delta.D.sub_point(&delta.Q.get_element());
        let A2_plus_eDmQ = self.A2 + D_minus_Q * e.clone();
        if z1G == A1_plus_eQ && z2G == A3_plus_eE && z2Y == A2_plus_eDmQ {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::*;
    use crate::{FE, GE};

    #[test]
    fn test_correct_homo_elgamal() {
        let witness = HomoElGamalDlogWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let y: FE = ECScalar::new_random();
        let Y = G.clone() * &y;
        let D = G.clone() * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let Q = G.clone() * &witness.x;
        let delta = HomoElGamalDlogStatement { G, Y, Q, D, E };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    // TODO: add more fail scenarios
    #[test]
    #[should_panic]
    fn test_wrong_homo_elgamal() {
        // test for Q = (x+1)G
        let witness = HomoElGamalDlogWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let y: FE = ECScalar::new_random();
        let Y = G.clone() * &y;
        let D = G.clone() * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r + G.clone();
        let Q = G.clone() * &witness.x + G.clone();
        let delta = HomoElGamalDlogStatement { G, Y, Q, D, E };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }
}
