use std::fmt::Debug;

use curv::elliptic::curves::traits::ECPoint;

/// Diffie Hellman Key Exchange:
/// TO RUN:
/// cargo run --example diffie_hellman_key_exchange -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example diffie_hellman_key_exchange -- secp256k1
///
/// notice: this library includes also a more involved ECDH scheme. see
/// dh_key_exchange_variant_with_pok_comm.rs

pub fn ecdh<P>()
where
    P: ECPoint + Clone + Debug,
    P::Scalar: Clone,
{
    use curv::cryptographic_primitives::twoparty::dh_key_exchange::{
        compute_pubkey, Party1FirstMessage, Party2FirstMessage,
    };

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

fn main() {
    let curve_name = std::env::args().nth(1);
    match curve_name.as_ref().map(|s| s.as_str()) {
        Some("secp256k1") => ecdh::<curv::elliptic::curves::secp256_k1::GE>(),
        Some("ristretto") => ecdh::<curv::elliptic::curves::curve_ristretto::GE>(),
        Some("ed25519") => ecdh::<curv::elliptic::curves::ed25519::GE>(),
        Some("bls12_381") => ecdh::<curv::elliptic::curves::bls12_381::g1::GE>(),
        Some("p256") => ecdh::<curv::elliptic::curves::p256::GE>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
