extern crate curv;

/// Diffie Hellman Key Exchange:
/// TO RUN:
/// cargo run --example diffie_hellman_key_exchange --features CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example diffie_hellman_key_exchange --features ec_secp256k1
///
/// notice: this library includes also a more involved ECDH scheme. see
/// dh_key_exchange_variant_with_pok_comm.rs

#[cfg(feature = "ecc")]
pub fn ecdh() {
    use curv::cryptographic_primitives::twoparty::dh_key_exchange::{
        compute_pubkey, Party1FirstMessage, Party2FirstMessage,
    };

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

fn main() {
    #[cfg(feature = "ecc")]
    ecdh();
}
