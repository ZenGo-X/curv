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



use BigInt;
//#[cfg(feature="curvesecp256k1")]
//use secp256k1instance::{SK,PK,GE,FE};
//#[cfg(feature="curve25519-dalek")]
//use curve25519instance::{SK,PK,GE,FE};
use super::ProofError;
use FE;
use GE;


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


pub trait ProveDLog {
    fn prove(sk: &FE) -> DLogProof;

    fn verify(proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(sk: &FE) -> DLogProof {
        let ec_point: GE = ECPoint::new();
        let generator_x = ec_point.get_x_coor_as_big_int();
        let sk_t_rand_commitment: FE = ECScalar::new_random();
        let curve_order = sk_t_rand_commitment.get_q();
        let pk_t_rand_commitment = ec_point.scalar_mul(&sk_t_rand_commitment.get_element());
        let ec_point: GE = ECPoint::new();
        let pk = ec_point.scalar_mul(&sk.get_element());
        let challenge = HSha256::create_hash(vec![
            &pk_t_rand_commitment.get_x_coor_as_big_int(),
            &generator_x,
            &pk.get_x_coor_as_big_int(),
        ]);
        let challenge_fe: FE = ECScalar::from_big_int(&challenge);
        let challenge_mul_sk = challenge_fe.mul(&sk.get_element());
        let challenge_response = sk_t_rand_commitment.sub(&challenge_mul_sk.get_element());


        DLogProof {
            pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    fn verify(proof: &DLogProof) -> Result<(), ProofError> {
        let ec_point: GE = ECPoint::new();
        let challenge = HSha256::create_hash(vec![
            &proof.pk_t_rand_commitment.get_x_coor_as_big_int(),
            &ec_point.get_x_coor_as_big_int(),
            &proof.pk.get_x_coor_as_big_int(),
        ]);

        let sk_challenge: FE = ECScalar::from_big_int(&challenge);
        let pk = proof.pk.clone();
        let pk_challenge = pk.scalar_mul(&sk_challenge.get_element());

        let base_point: GE = ECPoint::new();
        //let sk_challenge_response : FE = ECScalar::from_big_int(&proof.challenge_response);
        let sk_challenge_response: FE = proof.challenge_response.clone();
        let mut pk_verifier = base_point.scalar_mul(&sk_challenge_response.get_element());

        pk_verifier = pk_verifier.add_point(&pk_challenge.get_element());


        if pk_verifier.get_element() == proof.pk_t_rand_commitment.get_element() {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProofError;
    use cryptographic_primitives::proofs::dlog_zk_protocol::*;
    use serde_json;
    use BigInt;
    use FE;
    use GE;
    use PK;
    use SK;

    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use arithmetic::traits::Samplable;

    use elliptic::curves::traits::*;

    use cryptographic_primitives::hashing::hash_sha256::HSha256;
    use cryptographic_primitives::hashing::traits::Hash;

    #[test]
    fn test_dlog_proof() {
        let witness: FE = ECScalar::new_random();
        let dlog_proof = DLogProof::prove(&witness);
        let verified = DLogProof::verify(&dlog_proof);
        match verified {
            Ok(t) => println!("OK"),
            Err(e) => println!("error"),
        }
    }

}
