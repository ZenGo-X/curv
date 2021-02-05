/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::ProofError;
use crate::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use crate::cryptographic_primitives::commitments::traits::Commitment;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::traits::*;

/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (r) such that c = mG + rH.
/// witness: (r), statement: (c,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A = s*H for random s
/// prover calculates challenge e = H(G,H,c,A,m)
/// prover calculates z  = s + er,
/// prover sends pi = {e, m,A,c, z}
/// verifier checks that emG + zH  = A + ec
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PedersenBlindingProof<P: ECPoint> {
    e: P::Scalar,
    pub m: P::Scalar,
    a: P,
    pub com: P,
    z: P::Scalar,
}

impl<P> PedersenBlindingProof<P>
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize + Clone,
{
    //TODO: add self verification to prover proof
    pub fn prove(m: &P::Scalar, r: &P::Scalar) -> PedersenBlindingProof<P> {
        let h: P = ECPoint::base_point2();
        let mut s: P::Scalar = ECScalar::new_random();
        let a = h.scalar_mul(&s.get_element());
        let com: P = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_big_int(),
            &r.to_big_int(),
        );
        let g: P = ECPoint::generator();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &com.bytes_compressed_to_big_int(),
            &a.bytes_compressed_to_big_int(),
            &m.to_big_int(),
        ]);
        let e: P::Scalar = ECScalar::from(&challenge);

        let er = e.mul(&r.get_element());
        let z = s.add(&er.get_element());
        s.zeroize();
        PedersenBlindingProof {
            e,
            m: m.clone(),
            a,
            com,
            z,
        }
    }

    pub fn verify(proof: &PedersenBlindingProof<P>) -> Result<(), ProofError> {
        let g: P = ECPoint::generator();
        let h: P = ECPoint::base_point2();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &proof.com.bytes_compressed_to_big_int(),
            &proof.a.bytes_compressed_to_big_int(),
            &proof.m.to_big_int(),
        ]);

        let e: P::Scalar = ECScalar::from(&challenge);

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
    use super::*;

    crate::test_for_all_curves!(test_pedersen_blind_proof);
    fn test_pedersen_blind_proof<P>()
    where
        P: ECPoint + Clone,
        P::Scalar: Zeroize + Clone,
    {
        let m: P::Scalar = ECScalar::new_random();
        let r: P::Scalar = ECScalar::new_random();
        let pedersen_proof = PedersenBlindingProof::<P>::prove(&m, &r);
        let _verified =
            PedersenBlindingProof::verify(&pedersen_proof).expect("error pedersen blind");
    }
}
