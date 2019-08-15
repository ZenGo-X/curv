/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::ProofError;
use cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use cryptographic_primitives::commitments::traits::Commitment;
use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;
use elliptic::curves::traits::*;

use zeroize::Zeroize;
use {FE, GE};

/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (r) such that c = mG + rH.
/// witness: (r), statement: (c,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A = s*H for random s
/// prover calculates challenge e = H(G,H,c,A,m)
/// prover calculates z  = s + er,
/// prover sends pi = {e, m,A,c, z}
/// verifier checks that emG + zH  = A + ec
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
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
        let mut s: FE = ECScalar::new_random();
        let a = h.scalar_mul(&s.get_element());
        let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_big_int(),
            &r.to_big_int(),
        );
        let g: GE = ECPoint::generator();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &com.bytes_compressed_to_big_int(),
            &a.bytes_compressed_to_big_int(),
            &m.to_big_int(),
        ]);
        let e: FE = ECScalar::from(&challenge);

        let er = e.mul(&r.get_element());
        let z = s.add(&er.get_element());
        s.zeroize();
        PedersenBlindingProof {
            e,
            m: *m,
            a,
            com,
            z,
        }
    }

    fn verify(proof: &PedersenBlindingProof) -> Result<(), ProofError> {
        let g: GE = ECPoint::generator();
        let h = GE::base_point2();
        let challenge = HSha256::create_hash(&[
            &g.bytes_compressed_to_big_int(),
            &h.bytes_compressed_to_big_int(),
            &proof.com.bytes_compressed_to_big_int(),
            &proof.a.bytes_compressed_to_big_int(),
            &proof.m.to_big_int(),
        ]);

        let e: FE = ECScalar::from(&challenge);

        let zh = h.scalar_mul(&proof.z.get_element());
        let mg = g.scalar_mul(&proof.m.get_element());
        let emg = mg.scalar_mul(&e.get_element());
        let lhs = zh.add_point(&emg.get_element());
        let com_clone = proof.com;
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
