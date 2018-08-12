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
//#[cfg(feature="curvesecp256k1")]
//use secp256k1instance::{SK,PK,GE,FE};
//#[cfg(feature="curve25519-dalek")]
//use curve25519instance::{SK,PK,GE,FE};
use PK;
use SK;
use GE;
use FE;
use super::ProofError;

use arithmetic::traits::Converter;
use arithmetic::traits::Modulo;
use arithmetic::traits::Samplable;

use elliptic::curves::traits::*;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

#[derive(Clone, PartialEq, Debug)]
pub struct DLogProof {
    pub pk: GE,
    pub pk_t_rand_commitment: GE,
    pub challenge_response: FE,
}

/*
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RawDLogProof {
    pub pk: RawPoint,
    pub pk_t_rand_commitment: RawPoint,
    pub challenge_response: String, // Hex
}

impl From<DLogProof> for RawDLogProof {
    fn from(d_log_proof: DLogProof) -> Self {
        RawDLogProof {
            pk: RawPoint::from(d_log_proof.pk.to_point()),
            pk_t_rand_commitment: RawPoint::from(d_log_proof.pk_t_rand_commitment.to_point()),
            challenge_response: d_log_proof.challenge_response.to_hex(),
        }
    }
}

impl From<RawDLogProof> for DLogProof {
    fn from(raw_d_log_proof: RawDLogProof) -> Self {
        DLogProof {
            pk: PK::to_key(&Point::from(raw_d_log_proof.pk)),
            pk_t_rand_commitment: PK::to_key(&Point::from(raw_d_log_proof.pk_t_rand_commitment)),
            challenge_response: BigInt::from_hex(&raw_d_log_proof.challenge_response),
        }
    }
}
*/
pub trait ProveDLog {
    fn prove(sk: &FE) -> DLogProof;

    fn verify(proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(sk: &FE) -> DLogProof {
        let ec_point: GE = ECPoint::new();
        let generator_x = ec_point.get_x_coor_as_big_int();
        let sk_t_rand_commitment : FE = ECScalar::new_random();
        let curve_order = sk_t_rand_commitment.get_q();
        let pk_t_rand_commitment = ec_point.scalar_mul(&sk_t_rand_commitment.get_element());
        let ec_point: GE = ECPoint::new();
        let pk = ec_point.scalar_mul(&sk.get_element());
        let challenge = HSha256::create_hash(vec![
            &pk_t_rand_commitment.get_x_coor_as_big_int(),
            &generator_x,
            &pk.get_x_coor_as_big_int(),
        ]);
        let challenge_fe:FE = ECScalar::from_big_int(&challenge);
        let challenge_mul_sk =challenge_fe.mul(&sk.get_element());
        let challenge_response = sk_t_rand_commitment.sub(&challenge_mul_sk.get_element());
       // let challenge_response = BigInt::mod_sub(
       //     &sk_t_rand_commitment.to_big_int(),
       //     &BigInt::mod_mul(&challenge, &sk.to_big_int(), &curve_order),
       //     &curve_order,
       // );

        DLogProof {
            pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    fn verify( proof: &DLogProof) -> Result<(), ProofError> {
        let ec_point: GE = ECPoint::new();
        let challenge = HSha256::create_hash(vec![
            &proof.pk_t_rand_commitment.get_x_coor_as_big_int(),
            &ec_point.get_x_coor_as_big_int(),
            &proof.pk.get_x_coor_as_big_int(),
        ]);

        let sk_challenge : FE = ECScalar::from_big_int(&challenge);
        let pk = proof.pk.clone();
        let pk_challenge = pk.scalar_mul(&sk_challenge.get_element());

        let base_point: GE = ECPoint::new();
        //let sk_challenge_response : FE = ECScalar::from_big_int(&proof.challenge_response);
        let sk_challenge_response : FE = proof.challenge_response.clone();
        let mut pk_verifier = base_point.scalar_mul(&sk_challenge_response.get_element());

        pk_verifier =  pk_verifier.add_point(&pk_challenge.get_element());
        //let pk_verifier = match  ECPoint::add_point(&pk_verifier,&pk_challenge){
     //       Ok(pk_verifier) => pk_verifier,
     //       _error => return Err(ProofError),
     //   };

        if pk_verifier.get_element() == proof.pk_t_rand_commitment.get_element() {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::proofs::dlog_zk_protocol::*;
    use serde_json;
    use BigInt;
    use SK;
    use PK;
    use GE;
    use FE;
    use super::ProofError;

    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use arithmetic::traits::Samplable;

    use elliptic::curves::traits::*;

    use cryptographic_primitives::hashing::hash_sha256::HSha256;
    use cryptographic_primitives::hashing::traits::Hash;

    #[test]
    fn test_dlog_proof(){
        let witness : FE = ECScalar::new_random();
        let dlog_proof =  DLogProof::prove(&witness);
        let verified = DLogProof::verify(&dlog_proof);
        match verified{
            Ok(t) => println!("OK"),
            Err(e) => println!("error"),
        }
    }
    /*


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

        let s = serde_json::to_string(&RawDLogProof::from(d_log_proof))
            .expect("Failed in serialization");
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

        let rsd: RawDLogProof = serde_json::from_str(&sd).expect("Failed in serialization");

        assert_eq!(rsd, RawDLogProof::from(d_log_proof));
    }
*/
}
