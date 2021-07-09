/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::{Curve, Point, Scalar, ScalarZ};

use super::ProofError;
use crate::arithmetic::Converter;
use crate::BigInt;

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
#[serde(bound = "")]
pub struct DLogProof<E: Curve> {
    pub pk: Point<E>,
    pub pk_t_rand_commitment: Point<E>,
    pub challenge_response: ScalarZ<E>,
}

impl<E: Curve> DLogProof<E> {
    pub fn prove(sk: &Scalar<E>) -> DLogProof<E> {
        let generator = Point::<E>::generator();

        let sk_t_rand_commitment = Scalar::random();
        let pk_t_rand_commitment = generator * &sk_t_rand_commitment;

        let pk = Point::generator() * sk;

        let challenge = HSha256::create_hash(&[
            &BigInt::from_bytes(&pk_t_rand_commitment.to_bytes(true)),
            &BigInt::from_bytes(&generator.as_point().to_bytes(true)),
            &BigInt::from_bytes(&pk.to_bytes(true)),
        ]);

        let challenge_fe: ScalarZ<E> = ScalarZ::from(&challenge);
        let challenge_mul_sk = challenge_fe * sk;
        let challenge_response = &sk_t_rand_commitment - &challenge_mul_sk;
        DLogProof {
            pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    pub fn verify(proof: &DLogProof<E>) -> Result<(), ProofError> {
        let generator = Point::<E>::generator();

        let challenge = HSha256::create_hash(&[
            &BigInt::from_bytes(&proof.pk_t_rand_commitment.to_bytes(true)),
            &BigInt::from_bytes(&generator.as_point().to_bytes(true)),
            &BigInt::from_bytes(&proof.pk.to_bytes(true)),
        ]);

        let sk_challenge = ScalarZ::<E>::from(&challenge);
        let pk_challenge = &proof.pk * &sk_challenge;

        let pk_verifier = generator * &proof.challenge_response + pk_challenge;

        if pk_verifier == proof.pk_t_rand_commitment {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves!(test_dlog_proof);
    fn test_dlog_proof<E: Curve>() {
        let witness = Scalar::random();
        let dlog_proof = DLogProof::<E>::prove(&witness);
        assert!(DLogProof::verify(&dlog_proof).is_ok());
    }
}
