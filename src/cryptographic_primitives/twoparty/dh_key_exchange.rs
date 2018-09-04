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

//This is an implementation of a Difie Hellman Key Exchange.
// Party1 private key is "x",
// Party2 private key is "y",
//protocol:
// party1 sends a commitmemt to P1 = xG a commitment to a proof of knowledge of x
// party2 sends P2 and a proof of knowledge of y
// party1 verifies party2 proof decommit to P1 and and to the PoK
// party2 verifies party1 proof
// the shared secret is Q = xyG
// reference can be found in protocol 3.1 step 1 - 3(b) in the paper https://eprint.iacr.org/2017/552.pdf

use arithmetic::traits::Samplable;
use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;
use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;
use elliptic::curves::traits::*;
use BigInt;
use FE;
use GE;

const SECURITY_BITS: usize = 256;

#[derive(Debug)]
pub struct Party1FirstMessage {
    pub public_share: GE,
    secret_share: FE,

    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,
    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,
    d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct Party1SecondMessage {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct Party2FirstMessage {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Debug)]
pub struct Party2SecondMessage {}

impl Party1FirstMessage {
    pub fn create_commitments() -> Party1FirstMessage {
        let base: GE = ECPoint::new();
        let sk: FE = ECScalar::new_random();
        let pk = base.scalar_mul(&sk.get_element());
        let d_log_proof = DLogProof::prove(&sk);
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.get_x_coor_as_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.get_x_coor_as_big_int(),
            &zk_pok_blind_factor,
        );
        Party1FirstMessage {
            public_share: pk,
            secret_share: sk,
            pk_commitment,
            pk_commitment_blind_factor,
            zk_pok_commitment,
            zk_pok_blind_factor,
            d_log_proof,
        }
    }
}

impl Party1SecondMessage {
    pub fn verify_and_decommit(
        first_message: &Party1FirstMessage,
        proof: &DLogProof,
    ) -> Result<Party1SecondMessage, ProofError> {
        DLogProof::verify(&proof)?;
        Ok(Party1SecondMessage {
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

impl Party2FirstMessage {
    pub fn create() -> Party2FirstMessage {
        let base: GE = ECPoint::new();
        let sk: FE = ECScalar::new_random();
        let pk = base.scalar_mul(&sk.get_element());
        Party2FirstMessage {
            d_log_proof: DLogProof::prove(&sk),
            public_share: pk,
            secret_share: sk,
        }
    }
}

impl Party2SecondMessage {
    pub fn verify_commitments_and_dlog_proof(
        party_one_pk_commitment: &BigInt,
        party_one_zk_pok_commitment: &BigInt,
        party_one_zk_pok_blind_factor: &BigInt,
        party_one_public_share: &GE,
        party_one_pk_commitment_blind_factor: &BigInt,
        party_one_d_log_proof: &DLogProof,
    ) -> Result<Party2SecondMessage, ProofError> {
        let mut flag = true;
        match party_one_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.get_x_coor_as_big_int(),
                &party_one_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof
                    .pk_t_rand_commitment
                    .get_x_coor_as_big_int(),
                &party_one_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof)?;
        Ok(Party2SecondMessage {})
    }
}

pub fn compute_pubkey_party1(
    party_one_first_message: &Party1FirstMessage,
    party_two_first_message_public_share: &GE,
) -> GE {
    let pubkey = party_two_first_message_public_share.clone();
    pubkey.scalar_mul(&party_one_first_message.secret_share.get_element())
}
pub fn compute_pubkey_party2(
    party_two_first_message: &Party2FirstMessage,
    party_one_first_message_public_share: &GE,
) -> GE {
    let pubkey = party_one_first_message_public_share.clone();
    pubkey.scalar_mul(&party_two_first_message.secret_share.get_element())
}
pub fn compute_pubkey(secret_share: &FE, public_share: &GE) -> GE {
    let pubkey = public_share.clone();
    pubkey.scalar_mul(&secret_share.get_element())
}
#[cfg(test)]
mod tests {
    use cryptographic_primitives::twoparty::dh_key_exchange::*;

    #[test]
    fn test_full_key_gen() {
        let party_one_first_message = Party1FirstMessage::create_commitments();
        let party_two_first_message = Party2FirstMessage::create();
        let party_one_second_message = Party1SecondMessage::verify_and_decommit(
            &party_one_first_message,
            &party_two_first_message.d_log_proof,
        ).expect("failed to verify and decommit");
        let _party_two_second_message = Party2SecondMessage::verify_commitments_and_dlog_proof(
            &party_one_first_message.pk_commitment,
            &party_one_first_message.zk_pok_commitment,
            &party_one_second_message.zk_pok_blind_factor,
            &party_one_second_message.public_share,
            &party_one_second_message.pk_commitment_blind_factor,
            &party_one_second_message.d_log_proof,
        ).expect("failed to verify commitments and DLog proof");
        assert_eq!(
            compute_pubkey_party2(
                &party_two_first_message,
                &party_one_first_message.public_share
            ),
            compute_pubkey_party1(
                &party_one_first_message,
                &party_two_first_message.public_share
            )
        );
    }
}
