/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::ProofError;
use crate::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use crate::cryptographic_primitives::commitments::traits::Commitment;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::traits::*;
use zeroize::Zeroize;

/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (m,r) such that c = mG + rH.
/// witness: (m,r), statement: c, The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A1 = s1*G , A2 = s2*H for random s1,s2
/// prover calculates challenge e = H(G,H,c,A1,A2)
/// prover calculates z1  = s1 + em, z2 = s2 + er
/// prover sends pi = {e, A1,A2,c, z1,z2}
///
/// verifier checks that z1*G + z2*H  = A1 + A2 + ec
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PedersenProof<P: ECPoint> {
    e: P::Scalar,
    a1: P,
    a2: P,
    pub com: P,
    z1: P::Scalar,
    z2: P::Scalar,
}

impl<P> PedersenProof<P>
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize,
{
    #[allow(clippy::many_single_char_names)]
    pub fn prove(m: &P::Scalar, r: &P::Scalar) -> PedersenProof<P> {
        let g: P = ECPoint::generator();
        let h: P = ECPoint::base_point2();
        let mut s1: P::Scalar = ECScalar::new_random();
        let mut s2: P::Scalar = ECScalar::new_random();
        let a1 = g.scalar_mul(&s1.get_element());
        let a2 = h.scalar_mul(&s2.get_element());
        let com: P = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_big_int(),
            &r.to_big_int(),
        );
        let g: P = ECPoint::generator();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &com.bytes_compressed_to_big_int(),
            &a1.bytes_compressed_to_big_int(),
            &a2.bytes_compressed_to_big_int(),
        ]);

        let e: P::Scalar = ECScalar::from(&challenge);

        let em = e.mul(&m.get_element());
        let z1 = s1.add(&em.get_element());
        let er = e.mul(&r.get_element());
        let z2 = s2.add(&er.get_element());
        s1.zeroize();
        s2.zeroize();

        PedersenProof {
            e,
            a1,
            a2,
            com,
            z1,
            z2,
        }
    }

    pub fn verify(proof: &PedersenProof<P>) -> Result<(), ProofError> {
        let g: P = ECPoint::generator();
        let h: P = ECPoint::base_point2();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &proof.com.bytes_compressed_to_big_int(),
            &proof.a1.bytes_compressed_to_big_int(),
            &proof.a2.bytes_compressed_to_big_int(),
        ]);
        let e: P::Scalar = ECScalar::from(&challenge);

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
    use super::*;

    crate::test_for_all_curves!(test_pedersen_proof);
    fn test_pedersen_proof<P>()
    where
        P: ECPoint + Clone,
        P::Scalar: Zeroize,
    {
        let m: P::Scalar = ECScalar::new_random();
        let r: P::Scalar = ECScalar::new_random();
        let pedersen_proof = PedersenProof::<P>::prove(&m, &r);
        PedersenProof::verify(&pedersen_proof).expect("error pedersen");
    }
}
