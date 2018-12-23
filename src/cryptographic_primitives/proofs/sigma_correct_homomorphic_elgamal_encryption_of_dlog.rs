#![allow(non_snake_case)]
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
/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, Q, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG, Q = xG
///
use super::ProofError;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use elliptic::curves::traits::*;
use FE;
use GE;

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
        let s1: FE = ECScalar::new_random();
        let s2: FE = ECScalar::new_random();
        let A1 = delta.G.clone() * &s1;
        let A2 = delta.Y.clone() * &s2;
        let A3 = delta.G.clone() * &s2;
        let e =
            HSha256::create_hash_from_ge(&[&A1, &A2, &A3, &delta.G, &delta.Y, &delta.D, &delta.E]);
        let z1 = s1.add(&e.mul(&w.x.get_element()).get_element());
        let z2 = s2.add(&e.mul(&w.r.get_element()).get_element());

        HomoELGamalDlogProof { A1, A2, A3, z1, z2 }
    }

    pub fn verify(&self, delta: &HomoElGamalDlogStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.A1, &self.A2, &self.A3, &delta.G, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1G = delta.G.clone() * &self.z1;
        let z2Y = delta.Y.clone() * &self.z2;
        let z2G = delta.G.clone() * &self.z2;
        let A1_plus_eQ = self.A1.clone() + delta.Q.clone() * &e;
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * &e;
        let D_minus_Q = delta.D.sub_point(&delta.Q.get_element());
        let A2_plus_eDmQ = self.A2.clone() + D_minus_Q * &e;
        if z1G == A1_plus_eQ && z2G == A3_plus_eE && z2Y == A2_plus_eDmQ {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::*;
    use {FE, GE};

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
