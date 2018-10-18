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
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG
///
use super::ProofError;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use elliptic::curves::traits::*;
use FE;
use GE;

#[derive(Clone, PartialEq, Debug)]
pub struct HomoELGamalProof {
    pub T: GE,
    pub A3: GE,
    pub z1: FE,
    pub z2: FE,
}

#[derive(Clone, PartialEq, Debug)]
pub struct hegWitness {
    pub r: FE,
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug)]
pub struct hegStatement {
    pub G: GE,
    pub Y: GE,
    pub D: GE,
    pub E: GE,
}

impl HomoELGamalProof {
    pub fn prove(w: &hegWitness, delta: &hegStatement) -> HomoELGamalProof {
        let base_point: GE = ECPoint::generator();
        let s1: FE = ECScalar::new_random();
        let s2: FE = ECScalar::new_random();
        let A1 = delta.G.clone() * &s1;
        let A2 = delta.Y.clone() * &s2;
        let A3 = delta.G.clone() * &s2;
        let T = A1 + A2;
        let e = HSha256::create_hash_from_ge(&[&T, &A3, &delta.G, &delta.Y, &delta.D, &delta.E]);
        let z1 = s1.add(&e.mul(&w.x.get_element()).get_element());
        let z2 = s2.add(&e.mul(&w.r.get_element()).get_element());

        HomoELGamalProof { T, A3, z1, z2 }
    }

    pub fn verify(&self, delta: &hegStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.T, &self.A3, &delta.G, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1G_plus_z2Y = delta.G.clone() * &self.z1 + delta.Y.clone() * &self.z2;
        let T_plus_eD = self.T.clone() + delta.D.clone() * &e;
        let z2G = delta.G.clone() * &self.z2;
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * &e;
        if z1G_plus_z2Y.get_element() == T_plus_eD.get_element()
            && z2G.get_element() == A3_plus_eE.get_element()
        {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_correct_homomrphic_elgamal_enc::*;
    use elliptic::curves::traits::*;
    use {FE, GE};

    #[test]
    fn test_correct_homo_elgamal() {
        let witness = hegWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let y: FE = ECScalar::new_random();
        let Y = G.clone() * &y;
        let D = G.clone() * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let delta = hegStatement { G, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_wrong_homo_elgamal() {
        // test for E = (r+1)G
        let witness = hegWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let y: FE = ECScalar::new_random();
        let Y = G.clone() * &y;
        let D = G.clone() * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r + G.clone();
        let delta = hegStatement { G, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

}
