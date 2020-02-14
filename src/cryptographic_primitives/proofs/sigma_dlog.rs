/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/
use serde::{Deserialize, Serialize};

use super::ProofError;
use crate::FE;
use crate::GE;

use crate::elliptic::curves::traits::*;

use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use zeroize::Zeroize;

/// This is implementation of Schnorr's identification protocol for elliptic curve groups or a
/// sigma protocol for Proof of knowledge of the discrete log of an Elliptic-curve point:
/// C.P. Schnorr. Efficient Identification and Signatures for Smart Cards. In
/// CRYPTO 1989, Springer (LNCS 435), pages 239–252, 1990.
/// https://pdfs.semanticscholar.org/8d69/c06d48b618a090dd19185aea7a13def894a5.pdf.
///
/// The protocol is using Fiat-Shamir Transform: Amos Fiat and Adi Shamir.
/// How to prove yourself: Practical solutions to identification and signature problems.
/// In Advances in Cryptology - CRYPTO ’86, Santa Barbara, California, USA, 1986, Proceedings,
/// pages 186–194, 1986.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DLogProof {
    pub pk: GE,
    pub pk_t_rand_commitment: GE,
    pub challenge_response: FE,
}

pub trait ProveDLog {
    fn prove(sk: &FE) -> DLogProof;

    fn verify(proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(sk: &FE) -> DLogProof {
        let base_point: GE = ECPoint::generator();
        let generator_x = base_point.bytes_compressed_to_big_int();
        let mut sk_t_rand_commitment: FE = ECScalar::new_random();
        let pk_t_rand_commitment = base_point.scalar_mul(&sk_t_rand_commitment.get_element());
        let ec_point: GE = ECPoint::generator();
        let pk = ec_point.scalar_mul(&sk.get_element());
        let challenge = HSha256::create_hash(&[
            &pk_t_rand_commitment.bytes_compressed_to_big_int(),
            &generator_x,
            &pk.bytes_compressed_to_big_int(),
        ]);
        let challenge_fe: FE = ECScalar::from(&challenge);
        let challenge_mul_sk = challenge_fe.mul(&sk.get_element());
        let challenge_response = sk_t_rand_commitment.sub(&challenge_mul_sk.get_element());
        sk_t_rand_commitment.zeroize();
        DLogProof {
            pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    fn verify(proof: &DLogProof) -> Result<(), ProofError> {
        let ec_point: GE = ECPoint::generator();
        let challenge = HSha256::create_hash(&[
            &proof.pk_t_rand_commitment.bytes_compressed_to_big_int(),
            &ec_point.bytes_compressed_to_big_int(),
            &proof.pk.bytes_compressed_to_big_int(),
        ]);

        let sk_challenge: FE = ECScalar::from(&challenge);
        let pk = proof.pk;
        let pk_challenge = pk.scalar_mul(&sk_challenge.get_element());

        let base_point: GE = ECPoint::generator();

        let mut pk_verifier = base_point.scalar_mul(&proof.challenge_response.get_element());

        pk_verifier = pk_verifier.add_point(&pk_challenge.get_element());

        if pk_verifier == proof.pk_t_rand_commitment {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptographic_primitives::proofs::sigma_dlog::*;
    use crate::FE;

    #[test]
    fn test_dlog_proof() {
        let witness: FE = ECScalar::new_random();
        let dlog_proof = DLogProof::prove(&witness);
        let verified = DLogProof::verify(&dlog_proof);

        assert!(verified.is_ok())
    }
}
