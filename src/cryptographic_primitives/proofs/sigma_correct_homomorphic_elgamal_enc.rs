#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::ProofError;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use elliptic::curves::traits::*;
use zeroize::Zeroize;
use FE;
use GE;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalProof {
    pub T: GE,
    pub A3: GE,
    pub z1: FE,
    pub z2: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalWitness {
    pub r: FE,
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalStatement {
    pub G: GE,
    pub H: GE,
    pub Y: GE,
    pub D: GE,
    pub E: GE,
}

impl HomoELGamalProof {
    pub fn prove(w: &HomoElGamalWitness, delta: &HomoElGamalStatement) -> HomoELGamalProof {
        let mut s1: FE = ECScalar::new_random();
        let mut s2: FE = ECScalar::new_random();
        let mut A1 = delta.H * s1;
        let mut A2 = delta.Y * s2;
        let A3 = delta.G * s2;
        let T = A1 + A2;
        let e = HSha256::create_hash_from_ge(&[
            &T, &A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        // dealing with zero field element
        let z1 = if w.x != FE::zero() { s1 + w.x * e } else { s1 };
        let z2 = s2 + w.r * e;
        s1.zeroize();
        s2.zeroize();
        A1.zeroize();
        A2.zeroize();
        HomoELGamalProof { T, A3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.T, &self.A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1H_plus_z2Y = delta.H * self.z1 + delta.Y * self.z2;
        let T_plus_eD = self.T + delta.D * e;
        let z2G = delta.G * self.z2;
        let A3_plus_eE = self.A3 + delta.E * e;
        if z1H_plus_z2Y == T_plus_eD && z2G == A3_plus_eE {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
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
            r: FE::new_random(),
            x: FE::new_random(),
        };
        let G: GE = GE::generator();
        let y: FE = FE::new_random();
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
