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
use crate::elliptic::curves::traits::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair<P: ECPoint> {
    pub public_share: P,
    secret_share: P::Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party1FirstMessage<P: ECPoint> {
    pub public_share: P,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party2FirstMessage<P: ECPoint> {
    pub public_share: P,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {}

impl<P> Party1FirstMessage<P>
where P: ECPoint + Clone,
      P::Scalar: Clone,
{
    pub fn first() -> (Party1FirstMessage<P>, EcKeyPair<P>) {
        let base: P = ECPoint::generator();

        let secret_share: P::Scalar = ECScalar::new_random();

        let public_share = base * secret_share.clone();

        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: P::Scalar) -> (Party1FirstMessage<P>, EcKeyPair<P>) {
        let base: P = ECPoint::generator();
        let public_share = base * secret_share.clone();

        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party1FirstMessage { public_share }, ec_key_pair)
    }
}

impl<P> Party2FirstMessage<P>
where P: ECPoint + Clone,
      P::Scalar: Clone,
{
    pub fn first() -> (Party2FirstMessage<P>, EcKeyPair<P>) {
        let base: P = ECPoint::generator();
        let secret_share: P::Scalar = ECScalar::new_random();
        let public_share = base * secret_share.clone();
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }

    pub fn first_with_fixed_secret_share(secret_share: P::Scalar) -> (Party2FirstMessage<P>, EcKeyPair<P>) {
        let base: P = ECPoint::generator();
        let public_share = base * secret_share.clone();
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (Party2FirstMessage { public_share }, ec_key_pair)
    }
}

pub fn compute_pubkey<P>(local_share: &EcKeyPair<P>, other_share_public_share: &P) -> P
where P: ECPoint + Clone,
      P::Scalar: Clone,
{
    other_share_public_share.clone() * local_share.secret_share.clone()
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use crate::cryptographic_primitives::twoparty::dh_key_exchange::*;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;
    use crate::test_for_all_curves;

    test_for_all_curves!(test_dh_key_exchange_random_shares);
    fn test_dh_key_exchange_random_shares<P>()
    where P: ECPoint + Clone + Debug,
          P::Scalar: Clone,
    {
        let (kg_party_one_first_message, kg_ec_key_pair_party1) = Party1FirstMessage::<P>::first();
        let (kg_party_two_first_message, kg_ec_key_pair_party2) = Party2FirstMessage::<P>::first();

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
    fn test_dh_key_exchange_fixed_shares<P>()
    where P: ECPoint + Clone + Debug,
          P::Scalar: Clone,
    {
        let secret_party_1: P::Scalar = ECScalar::from(&BigInt::one());
        let (kg_party_one_first_message, kg_ec_key_pair_party1) =
            Party1FirstMessage::<P>::first_with_fixed_secret_share(secret_party_1);
        let secret_party_2: P::Scalar = ECScalar::from(&BigInt::from(2));

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
        let g: P = ECPoint::generator();
        assert_eq!(
            compute_pubkey(
                &kg_ec_key_pair_party2,
                &kg_party_one_first_message.public_share
            ),
            g * secret_party_2
        );
    }
}
