use curv::elliptic::curves::*;

/// Diffie Hellman Key Exchange:
/// TO RUN:
/// cargo run --example diffie_hellman_key_exchange -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example diffie_hellman_key_exchange -- secp256k1
///
/// notice: this library includes also a more involved ECDH scheme. see
/// dh_key_exchange_variant_with_pok_comm.rs

pub fn ecdh<E: Curve>() {
    use curv::cryptographic_primitives::twoparty::dh_key_exchange::{
        compute_pubkey, Party1FirstMessage, Party2FirstMessage,
    };

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

fn main() {
    let curve_name = std::env::args().nth(1);
    match curve_name.as_deref() {
        Some("secp256k1") => ecdh::<Secp256k1>(),
        Some("ristretto") => ecdh::<Ristretto>(),
        Some("ed25519") => ecdh::<Ed25519>(),
        Some("bls12_381_1") => ecdh::<Bls12_381_1>(),
        Some("bls12_381_2") => ecdh::<Bls12_381_2>(),
        Some("p256") => ecdh::<Secp256r1>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
