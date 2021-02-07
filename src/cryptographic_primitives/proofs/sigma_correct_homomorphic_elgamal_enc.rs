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
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalProof<P: ECPoint> {
    pub T: P,
    pub A3: P,
    pub z1: P::Scalar,
    pub z2: P::Scalar,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalWitness<S: ECScalar> {
    pub r: S,
    pub x: S,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalStatement<P> {
    pub G: P,
    pub H: P,
    pub Y: P,
    pub D: P,
    pub E: P,
}

impl<P> HomoELGamalProof<P>
where
    P: ECPoint + Clone + Zeroize,
    P::Scalar: PartialEq + Clone + Zeroize,
{
    pub fn prove(
        w: &HomoElGamalWitness<P::Scalar>,
        delta: &HomoElGamalStatement<P>,
    ) -> HomoELGamalProof<P> {
        let mut s1: P::Scalar = ECScalar::new_random();
        let mut s2: P::Scalar = ECScalar::new_random();
        let mut A1 = delta.H.clone() * s1.clone();
        let mut A2 = delta.Y.clone() * s2.clone();
        let A3 = delta.G.clone() * s2.clone();
        let T = A1.clone() + A2.clone();
        let e = HSha256::create_hash_from_ge(&[
            &T, &A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        // dealing with zero field element
        let z1 = if w.x != P::Scalar::zero() {
            s1.clone() + w.x.clone() * e.clone()
        } else {
            s1.clone()
        };
        let z2 = s2.clone() + w.r.clone() * e;
        s1.zeroize();
        s2.zeroize();
        A1.zeroize();
        A2.zeroize();
        HomoELGamalProof { T, A3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement<P>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.T, &self.A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        let z1H_plus_z2Y = delta.H.clone() * self.z1.clone() + delta.Y.clone() * self.z2.clone();
        let T_plus_eD = self.T.clone() + delta.D.clone() * e.clone();
        let z2G = delta.G.clone() * self.z2.clone();
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * e;
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
    fn test_correct_general_homo_elgamal<P>()
    where
        P: ECPoint + Clone + Zeroize,
        P::Scalar: PartialEq + Clone + Zeroize,
    {
        let witness = HomoElGamalWitness::<P::Scalar> {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: P = ECPoint::generator();
        let h: P::Scalar = ECScalar::new_random();
        let H = G.clone() * h;
        let y: P::Scalar = ECScalar::new_random();
        let Y = G.clone() * y;
        let D = H.clone() * witness.x.clone() + Y.clone() * witness.r.clone();
        let E = G.clone() * witness.r.clone();
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves!(test_correct_homo_elgamal);
    fn test_correct_homo_elgamal<P: ECPoint>()
    where
        P: ECPoint + Clone + Zeroize,
        P::Scalar: PartialEq + Clone + Zeroize,
    {
        let witness = HomoElGamalWitness {
            r: P::Scalar::new_random(),
            x: P::Scalar::new_random(),
        };
        let G: P = ECPoint::generator();
        let y: P::Scalar = ECScalar::new_random();
        let Y = G.clone() * y;
        let D = G.clone() * witness.x.clone() + Y.clone() * witness.r.clone();
        let E = G.clone() * witness.r.clone();
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

    test_for_all_curves!(
        #[should_panic]
        test_wrong_homo_elgamal
    );
    fn test_wrong_homo_elgamal<P: ECPoint>()
    where
        P: ECPoint + Clone + Zeroize,
        P::Scalar: PartialEq + Clone + Zeroize,
    {
        // test for E = (r+1)G
        let witness = HomoElGamalWitness::<P::Scalar> {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: P = ECPoint::generator();
        let h: P::Scalar = ECScalar::new_random();
        let H = G.clone() * h;
        let y: P::Scalar = ECScalar::new_random();
        let Y = G.clone() * y;
        let D = H.clone() * witness.x.clone() + Y.clone() * witness.r.clone();
        let E = G.clone() * witness.r.clone() + G.clone();
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }
}
