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
use zeroize::Zeroize;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, Y, Q, D, E).
/// The relation R outputs 1 if D = xG+rY , E = rG, Q = xG
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalDlogProof<P: ECPoint> {
    pub A1: P,
    pub A2: P,
    pub A3: P,
    pub z1: P::Scalar,
    pub z2: P::Scalar,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogWitness<S: ECScalar> {
    pub r: S,
    pub x: S,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalDlogStatement<P: ECPoint> {
    pub G: P,
    pub Y: P,
    pub Q: P,
    pub D: P,
    pub E: P,
}

impl<P> HomoELGamalDlogProof<P>
where P: ECPoint + Clone,
      P::Scalar: Zeroize + Clone,
{
    pub fn prove(
        w: &HomoElGamalDlogWitness<P::Scalar>,
        delta: &HomoElGamalDlogStatement<P>,
    ) -> HomoELGamalDlogProof<P> {
        let mut s1: P::Scalar = ECScalar::new_random();
        let mut s2: P::Scalar = ECScalar::new_random();
        let A1 = delta.G.clone() * s1.clone();
        let A2 = delta.Y.clone() * s2.clone();
        let A3 = delta.G.clone() * s2.clone();
        let e =
            HSha256::create_hash_from_ge(&[&A1, &A2, &A3, &delta.G, &delta.Y, &delta.D, &delta.E]);
        let z1 = s1.clone() + e.clone() * w.x.clone();
        let z2 = s2.clone() + e * w.r.clone();
        s1.zeroize();
        s2.zeroize();
        HomoELGamalDlogProof { A1, A2, A3, z1, z2 }
    }

    pub fn verify(&self, delta: &HomoElGamalDlogStatement<P>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.A1, &self.A2, &self.A3, &delta.G, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1G = delta.G.clone() * self.z1.clone();
        let z2Y = delta.Y.clone() * self.z2.clone();
        let z2G = delta.G.clone() * self.z2.clone();
        let A1_plus_eQ = self.A1.clone() + delta.Q.clone() * e.clone();
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * e.clone();
        let D_minus_Q = delta.D.sub_point(&delta.Q.get_element());
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
    use crate::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::*;
    use crate::test_for_all_curves;

    test_for_all_curves!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<P>()
    where P: ECPoint + Clone,
          P::Scalar: Zeroize + Clone,
    {
        let witness = HomoElGamalDlogWitness::<P::Scalar> {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: P = ECPoint::generator();
        let y: P::Scalar = ECScalar::new_random();
        let Y = G.clone() * y;
        let D = G.clone() * witness.x.clone() + Y.clone() * witness.r.clone();
        let E = G.clone() * witness.r.clone();
        let Q = G.clone() * witness.x.clone();
        let delta = HomoElGamalDlogStatement { G, Y, Q, D, E };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    // TODO: add more fail scenarios
    test_for_all_curves!(#[should_panic] test_wrong_homo_elgamal);
    fn test_wrong_homo_elgamal<P>()
    where P: ECPoint + Clone,
          P::Scalar: Zeroize + Clone,
    {
        // test for Q = (x+1)G
        let witness = HomoElGamalDlogWitness::<P::Scalar> {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: P = ECPoint::generator();
        let y: P::Scalar = ECScalar::new_random();
        let Y = G.clone() * y;
        let D = G.clone() * witness.x.clone() + Y.clone() * witness.r.clone();
        let E = G.clone() * witness.r.clone() + G.clone();
        let Q = G.clone() * witness.x.clone() + G.clone();
        let delta = HomoElGamalDlogStatement { G, Y, Q, D, E };
        let proof = HomoELGamalDlogProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }
}
