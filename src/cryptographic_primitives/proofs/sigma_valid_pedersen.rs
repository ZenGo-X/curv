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
// TODO: abstract for use with elliptic curves other than secp256k1
use super::ProofError;
/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (m,r) such that c = mG + rH.
/// witness: (m,r), statement: c, The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A1 = s1*G , A2 = s2*H for random s1,s2
/// prover calculates challenge e = H(G,H,c,A1,A2)
/// prover calculates z1  = s1 + em, z2 = s2 + er
/// prover sends pi = {e, A1,A2,c, z1,z2}
///
/// verifier checks that z1*G + z2*H  = A1 + A2 + ec
use elliptic::curves::traits::*;

use cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use cryptographic_primitives::commitments::traits::Commitment;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

use {FE, GE};
#[derive(Clone, PartialEq, Debug)]
pub struct PedersenProof {
    e: FE,
    a1: GE,
    a2: GE,
    pub com: GE,
    z1: FE,
    z2: FE,
}

pub trait ProvePederesen {
    fn prove(m: &FE, r: &FE) -> PedersenProof;

    fn verify(proof: &PedersenProof) -> Result<(), ProofError>;
}

impl ProvePederesen for PedersenProof {
    fn prove(m: &FE, r: &FE) -> PedersenProof {
        let g: GE = ECPoint::generator();
        let h = GE::base_point2();
        let s1: FE = ECScalar::new_random();
        let s2: FE = ECScalar::new_random();
        let a1 = g.scalar_mul(&s1.get_element());
        let a2 = h.scalar_mul(&s2.get_element());
        let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_big_int(),
            &r.to_big_int(),
        );
        let g: GE = ECPoint::generator();
        let challenge = HSha256::create_hash(&vec![
            &g.x_coor(),
            &h.x_coor(),
            &com.x_coor(),
            &a1.x_coor(),
            &a2.x_coor(),
        ]);

        let e: FE = ECScalar::from(&challenge);

        let em = e.mul(&m.get_element());
        let z1 = s1.add(&em.get_element());
        let er = e.mul(&r.get_element());
        let z2 = s2.add(&er.get_element());
        PedersenProof {
            e,
            a1,
            a2,
            com,
            z1,
            z2,
        }
    }

    fn verify(proof: &PedersenProof) -> Result<(), ProofError> {
        let g: GE = ECPoint::generator();
        let h = GE::base_point2();
        let challenge = HSha256::create_hash(&vec![
            &g.x_coor(),
            &h.x_coor(),
            &proof.com.x_coor(),
            &proof.a1.x_coor(),
            &proof.a2.x_coor(),
        ]);
        let e: FE = ECScalar::from(&challenge);

        let z1g = g.scalar_mul(&proof.z1.get_element());
        let z2h = h.scalar_mul(&proof.z2.get_element());
        let lhs = z1g.add_point(&z2h.get_element());
        let rhs = proof.a1.add_point(&proof.a2.get_element());
        let com_clone = proof.com.clone();
        let ecom = com_clone.scalar_mul(&e.get_element());
        let rhs = rhs.add_point(&ecom.get_element());

        if lhs == rhs {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_valid_pedersen::*;
    use FE;

    #[test]
    fn test_pedersen_proof() {
        let m: FE = ECScalar::new_random();
        let r: FE = ECScalar::new_random();
        let pedersen_proof = PedersenProof::prove(&m, &r);
        PedersenProof::verify(&pedersen_proof).expect("error pedersen");
    }

}
