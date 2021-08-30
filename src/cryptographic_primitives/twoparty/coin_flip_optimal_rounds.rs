/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::fmt::Debug;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use crate::cryptographic_primitives::proofs::sigma_valid_pedersen_blind::PedersenBlindingProof;
use crate::elliptic::curves::traits::*;

/// based on How To Simulate It – A Tutorial on the Simulation
/// Proof Technique. protocol 7.3: Multiple coin tossing. which provide simulatble constant round
/// coin toss
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = "PedersenProof<P>: Clone"))]
#[derivative(Debug(bound = "PedersenProof<P>: Debug"))]
#[derivative(PartialEq(bound = "PedersenProof<P>: PartialEq"))]
#[serde(bound(serialize = "PedersenProof<P>: Serialize"))]
#[serde(bound(deserialize = "PedersenProof<P>:  Deserialize<'de>"))]
pub struct Party1FirstMessage<P: ECPoint> {
    pub proof: PedersenProof<P>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Party2FirstMessage<P: ECPoint> {
    pub seed: P::Scalar,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Party1SecondMessage<P: ECPoint> {
    pub proof: PedersenBlindingProof<P>,
    pub seed: P::Scalar,
}
impl<P> Party1FirstMessage<P>
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize,
{
    pub fn commit() -> (Party1FirstMessage<P>, P::Scalar, P::Scalar) {
        let seed: P::Scalar = ECScalar::new_random();
        let blinding: P::Scalar = ECScalar::new_random();
        let proof = PedersenProof::prove(&seed, &blinding);
        (Party1FirstMessage { proof }, seed, blinding)
    }
}
impl<P> Party2FirstMessage<P>
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize + Clone,
{
    pub fn share(proof: &PedersenProof<P>) -> Party2FirstMessage<P> {
        PedersenProof::verify(proof).expect("{(m,r),c} proof failed");
        let seed: P::Scalar = ECScalar::new_random();
        Party2FirstMessage { seed }
    }
}
impl<P> Party1SecondMessage<P>
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize + Clone,
{
    pub fn reveal(
        party2seed: &P::Scalar,
        party1seed: &P::Scalar,
        party1blinding: &P::Scalar,
    ) -> (Party1SecondMessage<P>, P::Scalar) {
        let proof = PedersenBlindingProof::<P>::prove(party1seed, party1blinding);
        let coin_flip_result = &party1seed.to_big_int() ^ &party2seed.to_big_int();
        (
            Party1SecondMessage {
                proof,
                seed: party1seed.clone(),
            },
            ECScalar::from(&coin_flip_result),
        )
    }
}

// party2 finalize
pub fn finalize<P>(
    proof: &PedersenBlindingProof<P>,
    party2seed: &P::Scalar,
    party1comm: &P,
) -> P::Scalar
where
    P: ECPoint + Clone + Debug,
    P::Scalar: Zeroize + Clone,
{
    PedersenBlindingProof::<P>::verify(proof).expect("{r,(m,c)} proof failed");
    assert_eq!(&proof.com, party1comm);
    let coin_flip_result = &proof.m.to_big_int() ^ &party2seed.to_big_int();
    ECScalar::from(&coin_flip_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves!(test_coin_toss);
    pub fn test_coin_toss<P>()
    where
        P: ECPoint + Clone + Debug,
        P::Scalar: PartialEq + Clone + Debug + Zeroize,
    {
        let (party1_first_message, m1, r1) = Party1FirstMessage::<P>::commit();
        let party2_first_message = Party2FirstMessage::share(&party1_first_message.proof);
        let (party1_second_message, random1) =
            Party1SecondMessage::<P>::reveal(&party2_first_message.seed, &m1, &r1);
        let random2 = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        assert_eq!(random1, random2)
    }
}
