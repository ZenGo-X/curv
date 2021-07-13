/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

//! in ECDH Alice chooses at random a secret "a" and sends Bob public key A = aG
//! Bob chooses at random a secret "b" and sends to Alice B = bG.
//! Both parties can compute a joint secret: C = aB = bA = abG which cannot be computed by
//! a man in the middle attacker.

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::{Curve, Point, Scalar};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EcKeyPair<E: Curve> {
    pub public_share: Point<E>,
    secret_share: Scalar<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party1FirstMessage<E: Curve> {
    pub public_share: Point<E>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Party2FirstMessage<E: Curve> {
    pub public_share: Point<E>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {}

impl<E: Curve> Party1FirstMessage<E> {
    pub fn first() -> (Party1FirstMessage<E>, EcKeyPair<E>) {
        let base = Point::<E>::generator();

        let secret_share = Scalar::random();

        let public_share = base * &secret_share;

        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(
        secret_share: Scalar<E>,
    ) -> (Party1FirstMessage<E>, EcKeyPair<E>) {
        let public_share = Point::generator() * secret_share.clone();

        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }
}

impl<E: Curve> Party2FirstMessage<E> {
    pub fn first() -> (Party2FirstMessage<E>, EcKeyPair<E>) {
        let base = Point::<E>::generator();
        let secret_share = Scalar::random();
        let public_share = base * &secret_share;
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(
        secret_share: Scalar<E>,
    ) -> (Party2FirstMessage<E>, EcKeyPair<E>) {
        let public_share = Point::generator() * &secret_share;
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
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
    use crate::cryptographic_primitives::twoparty::dh_key_exchange::*;
    use crate::elliptic::curves::Curve;
    use crate::test_for_all_curves;
    use crate::BigInt;
    use std::convert::TryFrom;

    test_for_all_curves!(test_dh_key_exchange_random_shares);
    fn test_dh_key_exchange_random_shares<E: Curve>() {
        let (kg_party_one_first_message, kg_ec_key_pair_party1) = Party1FirstMessage::<E>::first();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) = Party2FirstMessage::<E>::first();

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

    test_for_all_curves!(test_dh_key_exchange_fixed_shares);
    fn test_dh_key_exchange_fixed_shares<E: Curve>() {
        let secret_party_1 = Scalar::try_from(&BigInt::from(1)).unwrap();
        let (kg_party_one_first_message, kg_ec_key_pair_party1) =
            Party1FirstMessage::<E>::first_with_fixed_secret_share(secret_party_1);
        let secret_party_2 = Scalar::try_from(&BigInt::from(2)).unwrap();

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            Party2FirstMessage::first_with_fixed_secret_share(secret_party_2.clone());

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
        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            Point::generator() * secret_party_2
        );
    }
}
