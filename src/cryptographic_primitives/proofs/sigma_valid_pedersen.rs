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
/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (m,r) such that c = mG + rH.
/// witness: (m,r), statement: c, The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A1 = s1*G , A2 = s2*H for random s1,s2
/// prover calculates challenge e = H(G,H,c,A1,A2)
/// prover calculates z1  = s1 + em, z2 = s2 + er
/// prover sends pi = {e, A1,A2,c, z1,z2}
///
/// verifier checks that z1* + z2*H  = A1 + A2 + ec
use BigInt;
use super::ProofError;
use arithmetic::traits::Converter;
use arithmetic::traits::Modulo;
use arithmetic::traits::Samplable;

use elliptic::curves::traits::*;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

use cryptographic_primitives::commitments::pedersen_commitment::pedersenCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

use elliptic::curves::secp256_k1::Secp256k1Scalar;
use elliptic::curves::secp256_k1::Secp256k1Point;

#[derive(Clone, PartialEq, Debug)]
pub struct PedersenProof {
    e : Secp256k1Scalar,
    A1: Secp256k1Point,
    A2: Secp256k1Point,
    pub com: Secp256k1Point,
    z1: Secp256k1Scalar,
    z2 :Secp256k1Scalar,

}
pub trait ProvePederesen {
    fn prove(m: &Secp256k1Scalar, r: &Secp256k1Scalar) -> PedersenProof;

    fn verify(proof: &PedersenProof) -> Result<(), ProofError>;
}

impl ProvePederesen for PedersenProof {
    fn prove(m: &Secp256k1Scalar, r: &Secp256k1Scalar) -> PedersenProof {
        let g: Secp256k1Point = ECPoint::new();
        let h = Secp256k1Point::base_point2();
        let s1: Secp256k1Scalar = ECScalar::new_random();
        let s2: Secp256k1Scalar = ECScalar::new_random();
        let A1 = g.scalar_mul(&s1.get_element());
        let A2 = h.scalar_mul(&s2.get_element());
        let com = pedersenCommitment::create_commitment_with_user_defined_randomness(&m.to_big_int(), &r.to_big_int());
        let G: Secp256k1Point = ECPoint::new();
        let challenge = HSha256::create_hash(vec![
            &G.get_x_coor_as_big_int(),
            &Secp256k1Point::base_point2().get_x_coor_as_big_int(),
            &com.get_x_coor_as_big_int(),
            &A1.get_x_coor_as_big_int(),
            &A2.get_x_coor_as_big_int(),
        ]);
        let e: Secp256k1Scalar = ECScalar::from_big_int(&challenge);
        let em = e.mul(&m.get_element());
        let z1 = s1.add(&em.get_element());
        let er = e.mul(&r.get_element());
        let z2 = s2.add(&er.get_element());
        PedersenProof{e, A1, A2, com, z1, z2}

    }

    fn verify(proof: &PedersenProof) -> Result<(), ProofError>{
        let g: Secp256k1Point = ECPoint::new();
        let h = Secp256k1Point::base_point2();
        let challenge = HSha256::create_hash(vec![
            &g.get_x_coor_as_big_int(),
            &h.get_x_coor_as_big_int(),
            &proof.com.get_x_coor_as_big_int(),
            &proof.A1.get_x_coor_as_big_int(),
            &proof.A2.get_x_coor_as_big_int(),
        ]);
        let e: Secp256k1Scalar = ECScalar::from_big_int(&challenge);
        let z1G = g.scalar_mul(&proof.z1.get_element());
        let z2H = h.scalar_mul(&proof.z2.get_element());
        let lhs = z1G.add_point(&z2H.get_element());
        let rhs = proof.A1.add_point(&proof.A2.get_element());
        let com_clone = proof.com.clone();
        let ecom = com_clone.scalar_mul(&e.get_element());
        let rhs = rhs.add_point(&ecom.get_element());
        if lhs.get_element() == rhs.get_element() {
            Ok(())
        } else {
            Err(ProofError)
        }

    }
}

#[cfg(test)]
mod tests {
    use BigInt;
    use super::ProofError;
    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use arithmetic::traits::Samplable;

    use elliptic::curves::traits::*;

    use cryptographic_primitives::hashing::hash_sha256::HSha256;
    use cryptographic_primitives::hashing::traits::Hash;

    use cryptographic_primitives::commitments::pedersen_commitment::pedersenCommitment;
    use cryptographic_primitives::proofs::sigma_valid_pedersen::*;

    use elliptic::curves::secp256_k1::Secp256k1Scalar;
    use elliptic::curves::secp256_k1::Secp256k1Point;

    #[test]
    fn test_pedersen_proof() {
        let m: Secp256k1Scalar = ECScalar::new_random();
        let r: Secp256k1Scalar = ECScalar::new_random();
        let pedersen_proof = PedersenProof::prove(&m, &r);
        PedersenProof::verify(&pedersen_proof).expect("error pedersen");
    }

}