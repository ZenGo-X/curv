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

/// This protocol is the elliptic curve form of the protocol from :
///  D. Chaum, T. P. Pedersen. Transferred cash grows in size. In Advances in Cryptology, EUROCRYPT , volume 658 of Lecture Notes in Computer Science, pages 390 - 407, 1993.
///  This is a proof of membership of DDH: (G, xG, yG, xyG)
/// The statement is (G1,H1, G2, H2), the witness is x. The relation outputs 1 if :
/// H1 = xG1, H2 = xG2
/// The protocol:
/// 1: Prover chooses A1 = s*G1 , A2 = sG2  for random s1,s2
/// prover calculates challenge e = H(G1,H1,G2,H2,A1,A2)
/// prover calculates z  = s + ex,
/// prover sends pi = {e, A1,A2,z}
///
/// verifier checks that zG1 = A1 + eH1, zG2 = A2 + eH2
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ECDDHProof<P: ECPoint> {
    pub a1: P,
    pub a2: P,
    pub z: P::Scalar,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement<P: ECPoint> {
    pub g1: P,
    pub h1: P,
    pub g2: P,
    pub h2: P,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness<S: ECScalar> {
    pub x: S,
}

// TODO: move to super and use in other sigma protocols
pub trait NISigmaProof<T, W, S> {
    fn prove(w: &W, delta: &S) -> T;

    fn verify(&self, delta: &S) -> Result<(), ProofError>;
}

impl<P> NISigmaProof<ECDDHProof<P>, ECDDHWitness<P::Scalar>, ECDDHStatement<P>> for ECDDHProof<P>
where P: ECPoint + Clone,
      P::Scalar: Zeroize + Clone,
{
    fn prove(w: &ECDDHWitness<P::Scalar>, delta: &ECDDHStatement<P>) -> ECDDHProof<P> {
        let mut s: P::Scalar = ECScalar::new_random();
        let a1 = delta.g1.clone() * s.clone();
        let a2 = delta.g2.clone() * s.clone();
        let e =
            HSha256::create_hash_from_ge(&[&delta.g1, &delta.h1, &delta.g2, &delta.h2, &a1, &a2]);
        let z = s.clone() + e * w.x.clone();
        s.zeroize();
        ECDDHProof { a1, a2, z }
    }

    fn verify(&self, delta: &ECDDHStatement<P>) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &delta.g1, &delta.h1, &delta.g2, &delta.h2, &self.a1, &self.a2,
        ]);
        let z_g1 = delta.g1.clone() * self.z.clone();
        let z_g2 = delta.g2.clone() * self.z.clone();
        let a1_plus_e_h1 = self.a1.clone() + delta.h1.clone() * e.clone();
        let a2_plus_e_h2 = self.a2.clone() + delta.h2.clone() * e.clone();
        if z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2 {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptographic_primitives::proofs::sigma_ec_ddh::*;
    use crate::elliptic::curves::traits::{ECPoint, ECScalar};
    use crate::test_for_all_curves;

    test_for_all_curves!(test_ecddh_proof);
    fn test_ecddh_proof<P>()
    where P: ECPoint + Clone,
          P::Scalar: Zeroize + Clone,
    {
        let x: P::Scalar = ECScalar::new_random();
        let g1: P = ECPoint::generator();
        let g2: P = ECPoint::base_point2();
        let h1 = g1.clone() * x.clone();
        let h2 = g2.clone() * x.clone();
        let delta = ECDDHStatement { g1, g2, h1, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    test_for_all_curves!(#[should_panic] test_wrong_ecddh_proof);
    fn test_wrong_ecddh_proof<P>()
    where P: ECPoint + Clone,
          P::Scalar: Zeroize + Clone,
    {
        let x: P::Scalar = ECScalar::new_random();
        let g1: P = ECPoint::generator();
        let g2: P = ECPoint::base_point2();
        let x2: P::Scalar = ECScalar::new_random();
        let h1 = g1.clone() * x.clone();
        let h2 = g2.clone() * x2.clone();
        let delta = ECDDHStatement { g1, g2, h1, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }
}
