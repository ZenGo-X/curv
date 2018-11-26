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
/// proof of knowledge of (r) such that c = mG + rH.
/// witness: (r), statement: (c,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A = s*H for random s
/// prover calculates challenge e = H(G,H,c,A,m)
/// prover calculates z  = s + er,
/// prover sends pi = {e, m,A,c, z}
///

/// verifier checks that emG + zH  = A + ec
use elliptic::curves::traits::*;

use cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use cryptographic_primitives::commitments::traits::Commitment;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

use {FE, GE};
#[derive(Clone, PartialEq, Debug)]
pub struct PedersenBlindingProof {
    e: FE,
    pub m: FE,
    a: GE,
    pub com: GE,
    z: FE,
}
pub trait ProvePederesenBlind {
    fn prove(m: &FE, r: &FE) -> PedersenBlindingProof;

    fn verify(proof: &PedersenBlindingProof) -> Result<(), ProofError>;
}
impl ProvePederesenBlind for PedersenBlindingProof {
    //TODO: add self verification to prover proof
    fn prove(m: &FE, r: &FE) -> PedersenBlindingProof {
        let h = GE::base_point2();
        let s: FE = ECScalar::new_random();
        let a = h.scalar_mul(&s.get_element());
        let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_big_int(),
            &r.to_big_int(),
        );
        let g: GE = ECPoint::generator();
        let challenge = HSha256::create_hash(&vec![
            &g.x_coor(),
            &h.x_coor(),
            &com.x_coor(),
            &a.x_coor(),
            &m.to_big_int(),
        ]);
        let e: FE = ECScalar::from(&challenge);

        let er = e.mul(&r.get_element());
        let z = s.add(&er.get_element());

        PedersenBlindingProof {
            e,
            m: m.clone(),
            a,
            com,
            z,
        }
    }

    fn verify(proof: &PedersenBlindingProof) -> Result<(), ProofError> {
        let g: GE = ECPoint::generator();
        let h = GE::base_point2();
        let challenge = HSha256::create_hash(&vec![
            &g.x_coor(),
            &h.x_coor(),
            &proof.com.x_coor(),
            &proof.a.x_coor(),
            &proof.m.to_big_int(),
        ]);

        let e: FE = ECScalar::from(&challenge);

        let zh = h.scalar_mul(&proof.z.get_element());
        let mg = g.scalar_mul(&proof.m.get_element());
        let emg = mg.scalar_mul(&e.get_element());
        let lhs = zh.add_point(&emg.get_element());
        let com_clone = proof.com.clone();
        let ecom = com_clone.scalar_mul(&e.get_element());
        let rhs = ecom.add_point(&proof.a.get_element());

        if lhs == rhs {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::sigma_valid_pedersen_blind::*;
    use FE;

    #[test]
    fn test_pedersen_blind_proof() {
        let m: FE = ECScalar::new_random();
        let r: FE = ECScalar::new_random();
        let pedersen_proof = PedersenBlindingProof::prove(&m, &r);
        let _verified =
            PedersenBlindingProof::verify(&pedersen_proof).expect("error pedersen blind");
    }

}
