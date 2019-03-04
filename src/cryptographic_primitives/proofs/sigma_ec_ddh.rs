/*
    curv

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/curv/blob/master/LICENSE>

*/

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
use super::ProofError;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use elliptic::curves::traits::*;
use zeroize::Zeroize;
use {FE, GE};

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement {
    pub g1: GE,
    pub h1: GE,
    pub g2: GE,
    pub h2: GE,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness {
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ECDDHProof {
    pub a1: GE,
    pub a2: GE,
    pub z: FE,
}

// TODO: move to super and use in other sigma protocols
pub trait NISigmaProof<T, W, S> {
    fn prove(w: &W, delta: &S) -> T;

    fn verify(&self, delta: &S) -> Result<(), ProofError>;
}

impl NISigmaProof<ECDDHProof, ECDDHWitness, ECDDHStatement> for ECDDHProof {
    fn prove(w: &ECDDHWitness, delta: &ECDDHStatement) -> ECDDHProof {
        let mut s: FE = ECScalar::new_random();
        let a1 = delta.g1 * s;
        let a2 = delta.g2 * s;
        let e =
            HSha256::create_hash_from_ge(&[&delta.g1, &delta.h1, &delta.g2, &delta.h2, &a1, &a2]);
        let z = s + e * w.x;
        s.zeroize();
        ECDDHProof { a1, a2, z }
    }

    fn verify(&self, delta: &ECDDHStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &delta.g1, &delta.h1, &delta.g2, &delta.h2, &self.a1, &self.a2,
        ]);
        let z_g1 = delta.g1 * self.z;
        let z_g2 = delta.g2 * self.z;
        let a1_plus_e_h1 = self.a1 + delta.h1 * e;
        let a2_plus_e_h2 = self.a2 + delta.h2 * e;
        if z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2 {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_ec_ddh::*;
    use elliptic::curves::traits::{ECPoint, ECScalar};
    use {FE, GE};

    #[test]
    fn test_ecddh_proof() {
        let x: FE = ECScalar::new_random();
        let g1: GE = ECPoint::generator();
        let g2: GE = GE::base_point2();
        let h1 = &g1 * &x;
        let h2 = &g2 * &x;
        let delta = ECDDHStatement { g1, g2, h1, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_wrong_ecddh_proof() {
        let x: FE = ECScalar::new_random();
        let g1: GE = ECPoint::generator();
        let g2: GE = GE::base_point2();
        let x2: FE = ECScalar::new_random();
        let h1 = &g1 * &x;
        let h2 = &g2 * &x2;
        let delta = ECDDHStatement { g1, g2, h1, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

}
