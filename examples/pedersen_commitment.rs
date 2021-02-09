use curv::arithmetic::{traits::*, BigInt};
use curv::elliptic::curves::traits::ECPoint;

use std::fmt::Debug;

/// Pedesen Commitment:
/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
/// TO RUN:
/// cargo run --example pedersen_commitment -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example pedersen_commitment -- ristretto
///
/// notice: this library includes also hash based commitments

pub fn ped_com<P>(message: &BigInt)
where
    P: ECPoint + Debug,
{
    use curv::arithmetic::traits::Samplable;
    use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
    use curv::cryptographic_primitives::commitments::traits::Commitment;

    let security_bits = 256;
    let blinding_factor = BigInt::sample(security_bits);
    let com = PedersenCommitment::<P>::create_commitment_with_user_defined_randomness(
        message,
        &blinding_factor,
    );

    println!(
        "\ncreated commitment with user defined randomness \n\n blinding_factor {} \n commitment: {:#?}",
        blinding_factor, com
    );
}

fn main() {
    let message = "commit me!";
    let message_bytes = message.as_bytes();
    let _message_bn = BigInt::from_bytes(Sign::Positive, message_bytes);
    let curve_name = std::env::args().nth(1);
    match curve_name.as_deref() {
        Some("secp256k1") => ped_com::<curv::elliptic::curves::secp256_k1::GE>(&_message_bn),
        Some("ristretto") => ped_com::<curv::elliptic::curves::curve_ristretto::GE>(&_message_bn),
        Some("ed25519") => ped_com::<curv::elliptic::curves::ed25519::GE>(&_message_bn),
        Some("bls12_381") => ped_com::<curv::elliptic::curves::bls12_381::g1::GE>(&_message_bn),
        Some("p256") => ped_com::<curv::elliptic::curves::p256::GE>(&_message_bn),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
