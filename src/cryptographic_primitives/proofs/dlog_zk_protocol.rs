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

//! This is implementation of Schnorr's identification protocol for elliptic curve groups or a
//! sigma protocol for Proof of knowledge of the discrete log of an Elliptic-curve point:
//! C.P. Schnorr. Efficient Identification and Signatures for Smart Cards. In
//! CRYPTO 1989, Springer (LNCS 435), pages 239–252, 1990.
//! https://pdfs.semanticscholar.org/8d69/c06d48b618a090dd19185aea7a13def894a5.pdf.
//!
//! The protocol is using Fiat-Shamir Transform: Amos Fiat and Adi Shamir.
//! How to prove yourself: Practical solutions to identification and signature problems.
//! In Advances in Cryptology - CRYPTO ’86, Santa Barbara, California, USA, 1986, Proceedings,
//! pages 186–194, 1986.

use BigInt;

use EC;
use PK;
use SK;

use super::ProofError;

use arithmetic::serde::serde_bigint;
use arithmetic::traits::Modulo;
use arithmetic::traits::Samplable;

use elliptic::curves::serde::serde_public_key;
use elliptic::curves::traits::*;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DLogProof {
    #[serde(with = "serde_public_key")]
    pub pk: PK,

    #[serde(with = "serde_public_key")]
    pub pk_t_rand_commitment: PK,

    #[serde(with = "serde_bigint")]
    pub challenge_response: BigInt,
}

pub trait ProveDLog {
    fn prove(ec_context: &EC, pk: &PK, sk: &SK) -> DLogProof;

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(ec_context: &EC, pk: &PK, sk: &SK) -> DLogProof {
        let mut pk_t_rand_commitment = PK::to_key(&PK::get_base_point());
        let sk_t_rand_commitment = SK::from_big_int(&BigInt::sample_below(&SK::get_q()));

        pk_t_rand_commitment
            .mul_assign(ec_context, &sk_t_rand_commitment)
            .expect("Assignment expected");

        let challenge = HSha256::create_hash(vec![
            &pk_t_rand_commitment.to_point().x,
            &PK::get_base_point().x,
            &pk.to_point().x,
        ]);

        let challenge_response = BigInt::mod_sub(
            &sk_t_rand_commitment.to_big_int(),
            &BigInt::mod_mul(&challenge, &sk.to_big_int(), &SK::get_q()),
            &SK::get_q(),
        );

        DLogProof {
            pk: *pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError> {
        let challenge = HSha256::create_hash(vec![
            &proof.pk_t_rand_commitment.to_point().x,
            &PK::get_base_point().x,
            &proof.pk.to_point().x,
        ]);

        let mut pk_challenge = proof.pk.clone();
        pk_challenge
            .mul_assign(ec_context, &SK::from_big_int(&challenge))
            .expect("Assignment expected");

        let mut pk_verifier = PK::to_key(&PK::get_base_point());
        pk_verifier
            .mul_assign(ec_context, &SK::from_big_int(&proof.challenge_response))
            .expect("Assignment expected");

        let pk_verifier = match pk_verifier.combine(&ec_context, &pk_challenge) {
            Ok(pk_verifier) => pk_verifier,
            _error => return Err(ProofError),
        };

        if pk_verifier == proof.pk_t_rand_commitment {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DLogProof;
    use serde_json;
    use BigInt;
    use EC;
    use PK;

    #[test]
    fn test_serialization() {
        let valid_key: [u8; 65] = [
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let s = EC::new();
        let d_log_proof = DLogProof {
            pk: PK::from_slice(&s, &valid_key).unwrap(),
            pk_t_rand_commitment: PK::from_slice(&s, &valid_key).unwrap(),
            challenge_response: BigInt::from(11),
        };

        let s = serde_json::to_string(&d_log_proof).expect("Failed in serialization");

        println!("{}", s);
        assert_eq!(
            s,
            "{\"pk\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"pk_t_rand_commitment\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"challenge_response\":\"b\"}"
        );
    }

    #[test]
    fn test_deserialization() {
        let valid_key: [u8; 65] = [
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let s = EC::new();
        let d_log_proof = DLogProof {
            pk: PK::from_slice(&s, &valid_key).unwrap(),
            pk_t_rand_commitment: PK::from_slice(&s, &valid_key).unwrap(),
            challenge_response: BigInt::from(11),
        };


        let sd = "{\"pk\":{\
                  \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
                  \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
                  \"pk_t_rand_commitment\":{\
                  \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
                  \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
                  \"challenge_response\":\"b\"}";

        let rsd: DLogProof = serde_json::from_str(&sd).expect("Failed in serialization");

        assert_eq!(rsd, d_log_proof);
    }
}
