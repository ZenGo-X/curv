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

// This is an implementation of string coin tossing of a string, to generate a random string between
//two non-trusting parties. Based on the
// the protocol and proof analysis  in "How To Simulate It – A Tutorial on the Simulation
// Proof Technique∗" (https://eprint.iacr.org/2016/046.pdf)

use cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use cryptographic_primitives::proofs::sigma_valid_pedersen::ProvePederesen;
use cryptographic_primitives::proofs::sigma_valid_pedersen_blind::PedersenBlindingProof;
use cryptographic_primitives::proofs::sigma_valid_pedersen_blind::ProvePederesenBlind;
use elliptic::curves::traits::*;

use elliptic::curves::secp256_k1::Secp256k1Point;
use elliptic::curves::secp256_k1::Secp256k1Scalar;

#[derive(Clone, PartialEq, Debug)]
pub struct Party1FirstMessage {
    pub proof: PedersenProof,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Party2FirstMessage {
    pub seed: Secp256k1Scalar,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Party1SecondMessage {
    pub proof: PedersenBlindingProof,
    pub seed: Secp256k1Scalar,
}

impl Party1FirstMessage {
    pub fn commit() -> (Party1FirstMessage, Secp256k1Scalar, Secp256k1Scalar) {
        let seed: Secp256k1Scalar = ECScalar::new_random();
        let blinding: Secp256k1Scalar = ECScalar::new_random();
        let proof = PedersenProof::prove(&seed, &blinding);
        (Party1FirstMessage { proof }, seed, blinding)
    }
}

impl Party2FirstMessage {
    pub fn share(proof: &PedersenProof) -> Party2FirstMessage {
        PedersenProof::verify(&proof).expect("{(m,r),c} proof failed");
        let seed: Secp256k1Scalar = ECScalar::new_random();
        Party2FirstMessage { seed }
    }
}

impl Party1SecondMessage {
    pub fn reveal(
        party2seed: &Secp256k1Scalar,
        party1seed: &Secp256k1Scalar,
        party1blinding: &Secp256k1Scalar,
    ) -> (Party1SecondMessage, Secp256k1Scalar) {
        let proof = PedersenBlindingProof::prove(&party1seed, &party1blinding);
        let coin_flip_result = &party1seed.to_big_int() ^ &party2seed.to_big_int();
        (
            Party1SecondMessage {
                proof,
                seed: party1seed.clone(),
            },
            ECScalar::from_big_int(&coin_flip_result),
        )
    }
}

// party2 finalize
pub fn finalize(
    proof: &PedersenBlindingProof,
    party2seed: &Secp256k1Scalar,
    party1comm: &Secp256k1Point,
) -> Secp256k1Scalar {
    PedersenBlindingProof::verify(&proof).expect("{r,(m,c)} proof failed");
    assert_eq!(&proof.com, party1comm);
    let coin_flip_result = &proof.m.to_big_int() ^ &party2seed.to_big_int();
    ECScalar::from_big_int(&coin_flip_result)
}

#[cfg(test)]
mod tests {
    use BigInt;

    use arithmetic::traits::Converter;
    use arithmetic::traits::Modulo;
    use arithmetic::traits::Samplable;

    use elliptic::curves::traits::*;

    use cryptographic_primitives::hashing::hash_sha256::HSha256;
    use cryptographic_primitives::hashing::traits::Hash;

    use cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
    use cryptographic_primitives::commitments::traits::Commitment;
    use cryptographic_primitives::proofs::sigma_valid_pedersen::*;
    use cryptographic_primitives::proofs::sigma_valid_pedersen_blind::*;
    use cryptographic_primitives::proofs::ProofError;
    use cryptographic_primitives::twoparty::coin_flip_optimal_rounds::*;

    use elliptic::curves::secp256_k1::Secp256k1Point;
    use elliptic::curves::secp256_k1::Secp256k1Scalar;
    #[test]
    pub fn test_coin_toss() {
        let (party1_first_message, m1, r1) = Party1FirstMessage::commit();
        let party2_first_message = Party2FirstMessage::share(&party1_first_message.proof);
        let (party1_second_message, random1) =
            Party1SecondMessage::reveal(&party2_first_message.seed, &m1, &r1);
        let random2 = finalize(
            &party1_second_message.proof,
            &party2_first_message.seed,
            &party1_first_message.proof.com,
        );
        assert_eq!(random1, random2)
    }
}
