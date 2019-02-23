/*
    Curv

    Copyright 2018 by Kzen Networks

    This file is part of curv library
    (https://github.com/KZen-networks/curv)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

//This is an implementation of a Diffie Hellman Key Exchange.
// Party1 private key is "x",
// Party2 private key is "y",
//protocol:
// party1 sends a commitmemt to P1 = xG a commitment to a proof of knowledge of x
// party2 sends P2 and a proof of knowledge of y
// party1 verifies party2 proof decommit to P1 and  to the PoK
// party2 verifies party1 proof
// the shared secret is Q = xyG
// reference can be found in protocol 3.1 step 1 - 3(b) in the paper https://eprint.iacr.org/2017/552.pdf

use elliptic::curves::traits::*;
use FE;
use GE;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1FirstMessage {
    pub public_share: GE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party2FirstMessage {
    pub public_share: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {}

impl Party1FirstMessage {
    pub fn first() -> (Party1FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();

        let public_share = base * secret_share;

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: FE) -> (Party1FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }
}

impl Party2FirstMessage {
    pub fn first() -> (Party2FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: FE) -> (Party2FirstMessage, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }
}

pub fn compute_pubkey(local_share: &EcKeyPair, other_share_public_share: &GE) -> GE {
    other_share_public_share * &local_share.secret_share
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::twoparty::dh_key_exchange::*;
    use elliptic::curves::traits::ECScalar;
    use BigInt;
    use {FE, GE};

    #[test]
    fn test_dh_key_exchange_random_shares() {
        let (kg_party_one_first_message, kg_ec_key_pair_party1) = Party1FirstMessage::first();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) = Party2FirstMessage::first();

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
    }

    #[test]
    fn test_dh_key_exchange_fixed_shares() {
        let secret_party_1: FE = ECScalar::from(&BigInt::one());
        let (kg_party_one_first_message, kg_ec_key_pair_party1) =
            Party1FirstMessage::first_with_fixed_secret_share(secret_party_1);
        let secret_party_2: FE = ECScalar::from(&BigInt::from(2));

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            Party2FirstMessage::first_with_fixed_secret_share(secret_party_2);

        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            compute_pubkey(
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.public_share
            )
        );
        let g: GE = GE::generator();
        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            g * secret_party_2
        );
    }

}
