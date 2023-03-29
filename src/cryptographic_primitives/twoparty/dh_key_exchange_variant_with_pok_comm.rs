/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

/// in ECDH Alice chooses at random a secret "a" and sends Bob public key A = aG
/// Bob chooses at random a secret "b" and sends to Alice B = bG.
/// Both parties can compute a joint secret: C =aB = bA = abG which cannot be computed by
/// a man in the middle attacker.
///
/// The variant below is to protect not only from man in the middle but also from malicious
/// Alice or Bob that can bias the result. The details of the protocol can be found in
/// https://eprint.iacr.org/2017/552.pdf protocol 3.1 first 3 steps.
use std::fmt::Debug;

use digest::Digest;
use serde::{Deserialize, Serialize};

use crate::arithmetic::traits::*;
use crate::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use crate::cryptographic_primitives::commitments::traits::Commitment;
use crate::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::cryptographic_primitives::proofs::ProofError;
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::BigInt;

const SECURITY_BITS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EcKeyPair<E: Curve> {
    pub public_share: Point<E>,
    secret_share: Scalar<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CommWitness<E: Curve, H: Digest + Clone> {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: Point<E>,
    pub d_log_proof: DLogProof<E, H>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1FirstMessage {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party2FirstMessage<E: Curve, H: Digest + Clone> {
    pub d_log_proof: DLogProof<E, H>,
    pub public_share: Point<E>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party1SecondMessage<E: Curve, H: Digest + Clone> {
    pub comm_witness: CommWitness<E, H>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {}

impl Party1FirstMessage {
    pub fn create_commitments<E: Curve, H: Digest + Clone>(
    ) -> (Party1FirstMessage, CommWitness<E, H>, EcKeyPair<E>) {
        let base = Point::<E>::generator();

        let secret_share = Scalar::random();

        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&public_share.to_bytes(true)),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&d_log_proof.pk_t_rand_commitment.to_bytes(true)),
            &zk_pok_blind_factor,
        );
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            Party1FirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share<E: Curve, H: Digest + Clone>(
        secret_share: Scalar<E>,
    ) -> (Party1FirstMessage, CommWitness<E, H>, EcKeyPair<E>) {
        let base = Point::<E>::generator();
        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&public_share.to_bytes(true)),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&d_log_proof.pk_t_rand_commitment.to_bytes(true)),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            Party1FirstMessage {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl<E: Curve, H: Digest + Clone> Party1SecondMessage<E, H> {
    pub fn verify_and_decommit(
        comm_witness: CommWitness<E, H>,
        proof: &DLogProof<E, H>,
    ) -> Result<Party1SecondMessage<E, H>, ProofError> {
        DLogProof::verify(proof)?;
        Ok(Party1SecondMessage { comm_witness })
    }
}
impl<E: Curve, H: Digest + Clone> Party2FirstMessage<E, H> {
    pub fn create() -> (Party2FirstMessage<E, H>, EcKeyPair<E>) {
        let base = Point::generator();
        let secret_share = Scalar::random();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            Party2FirstMessage {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(
        secret_share: Scalar<E>,
    ) -> (Party2FirstMessage<E, H>, EcKeyPair<E>) {
        let base = Point::generator();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            Party2FirstMessage {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }
}

impl Party2SecondMessage {
    pub fn verify_commitments_and_dlog_proof<E: Curve, H: Digest + Clone>(
        party_one_first_message: &Party1FirstMessage,
        party_one_second_message: &Party1SecondMessage<E, H>,
    ) -> Result<Party2SecondMessage, ProofError> {
        let party_one_pk_commitment = &party_one_first_message.pk_commitment;
        let party_one_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        if party_one_public_share.is_zero() {
            return Err(ProofError);
        }
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let mut flag = true;
        if party_one_pk_commitment
            != &HashCommitment::<H>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&party_one_public_share.to_bytes(true)),
                party_one_pk_commitment_blind_factor,
            )
        {
            flag = false
        };

        if party_one_zk_pok_commitment
            != &HashCommitment::<H>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&party_one_d_log_proof.pk_t_rand_commitment.to_bytes(true)),
                party_one_zk_pok_blind_factor,
            )
        {
            flag = false
        };

        assert!(flag);
        DLogProof::verify(party_one_d_log_proof)?;
        Ok(Party2SecondMessage {})
    }
}
pub fn compute_pubkey<E: Curve>(
    local_share: &EcKeyPair<E>,
    other_share_public_share: &Point<E>,
) -> Point<E> {
    other_share_public_share * &local_share.secret_share
}

#[cfg(test)]
mod tests {
    use crate::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;

    crate::test_for_all_curves_and_hashes!(test_dh_key_exchange);
    fn test_dh_key_exchange<E: Curve, H: Digest + Clone>() {
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            Party1FirstMessage::create_commitments::<E, H>();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            Party2FirstMessage::<E, H>::create();
        let kg_party_one_second_message = Party1SecondMessage::verify_and_decommit(
            kg_comm_witness,
            &kg_party_two_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");

        let _kg_party_two_second_message = Party2SecondMessage::verify_commitments_and_dlog_proof(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_second_message.comm_witness.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
    }
}
