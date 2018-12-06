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
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
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
pub struct HomoElGamalWitness {
    pub r: FE,
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug)]
pub struct HomoElGamalStatement {
    pub G: GE,
    pub H: GE,
    pub Y: GE,
    pub D: GE,
    pub E: GE,
}

impl HomoELGamalProof {
    pub fn prove(w: &HomoElGamalWitness, delta: &HomoElGamalStatement) -> HomoELGamalProof {
        let s1: FE = ECScalar::new_random();
        let s2: FE = ECScalar::new_random();
        let A1 = &delta.H * &s1;
        let A2 = &delta.Y * &s2;
        let A3 = &delta.G * &s2;
        let T = A1 + A2;
        let e = HSha256::create_hash_from_ge(&[
            &T, &A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        let mut z1 = s1.clone();
        // dealing with zero field element
        if w.x != FE::zero() {
            z1 = s1.add(&e.mul(&w.x.get_element()).get_element());
        }
        let z2 = s2.add(&e.mul(&w.r.get_element()).get_element());

        HomoELGamalProof { T, A3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.T, &self.A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1H_plus_z2Y = &delta.H * &self.z1 + &delta.Y * &self.z2;
        let T_plus_eD = self.T.clone() + delta.D.clone() * &e;
        let z2G = delta.G.clone() * &self.z2;
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * &e;
        if z1H_plus_z2Y == T_plus_eD && z2G == A3_plus_eE {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_correct_homomrphic_elgamal_enc::*;
    use {FE, GE};

    #[test]
    fn test_correct_general_homo_elgamal() {
        let witness = HomoElGamalWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let h: FE = ECScalar::new_random();
        let H = &G * &h;
        let y: FE = ECScalar::new_random();
        let Y = &G * &y;
        let D = &H * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[test]
    fn test_correct_homo_elgamal() {
        let witness = HomoElGamalWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let y: FE = ECScalar::new_random();
        let Y = &G * &y;
        let D = &G * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let delta = HomoElGamalStatement {
            G: G.clone(),
            H: G,
            Y,
            D,
            E,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_wrong_homo_elgamal() {
        // test for E = (r+1)G
        let witness = HomoElGamalWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let h: FE = ECScalar::new_random();
        let H = &G * &h;
        let y: FE = ECScalar::new_random();
        let Y = &G * &y;
        let D = &H * &witness.x + Y.clone() * &witness.r;
        let E = &G * &witness.r + G.clone();
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

}
