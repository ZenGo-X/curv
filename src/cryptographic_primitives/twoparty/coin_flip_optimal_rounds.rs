/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use crate::cryptographic_primitives::proofs::sigma_valid_pedersen_blind::PedersenBlindingProof;
use crate::elliptic::curves::{Curve, Point, Scalar};

/// based on How To Simulate It – A Tutorial on the Simulation
/// Proof Technique. protocol 7.3: Multiple coin tossing. which provide simulatble constant round
/// coin toss
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party1FirstMessage<E: Curve> {
    pub proof: PedersenProof<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party2FirstMessage<E: Curve> {
    pub seed: Scalar<E>,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party1SecondMessage<E: Curve> {
    pub proof: PedersenBlindingProof<E>,
    pub seed: Scalar<E>,
}
impl<E: Curve> Party1FirstMessage<E> {
    pub fn commit() -> (Party1FirstMessage<E>, Scalar<E>, Scalar<E>) {
        let seed = Scalar::random();
        let blinding = Scalar::random();
        let proof = PedersenProof::prove(&seed, &blinding);
        (Party1FirstMessage { proof }, seed, blinding)
    }
}
impl<E: Curve> Party2FirstMessage<E> {
    pub fn share(proof: &PedersenProof<E>) -> Party2FirstMessage<E> {
        PedersenProof::verify(proof).expect("{(m,r),c} proof failed");
        let seed = Scalar::random();
        Party2FirstMessage { seed }
    }
}
impl<E: Curve> Party1SecondMessage<E> {
    pub fn reveal(
        party2seed: &Scalar<E>,
        party1seed: &Scalar<E>,
        party1blinding: &Scalar<E>,
    ) -> (Party1SecondMessage<E>, Scalar<E>) {
        let proof = PedersenBlindingProof::<E>::prove(party1seed, party1blinding);
        let coin_flip_result = &party1seed.to_bigint() ^ &party2seed.to_bigint();
        (
            Party1SecondMessage {
                proof,
                seed: party1seed.clone(),
            },
            Scalar::from(&coin_flip_result),
        )
    }
}

// party2 finalize
pub fn finalize<E: Curve>(
    proof: &PedersenBlindingProof<E>,
    party2seed: &Scalar<E>,
    party1comm: &Point<E>,
) -> Scalar<E> {
    PedersenBlindingProof::<E>::verify(proof).expect("{r,(m,c)} proof failed");
    assert_eq!(&proof.com, party1comm);
    let coin_flip_result = &proof.m.to_bigint() ^ &party2seed.to_bigint();
    Scalar::from(&coin_flip_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves!(test_coin_toss);
    pub fn test_coin_toss<E: Curve>() {
        let (party1_first_message, m1, r1) = Party1FirstMessage::<E>::commit();
        let party2_first_message = Party2FirstMessage::share(&party1_first_message.proof);
        let (party1_second_message, random1) =
            Party1SecondMessage::<E>::reveal(&party2_first_message.seed, &m1, &r1);
        let random2 = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        assert_eq!(random1, random2)
    }
}
