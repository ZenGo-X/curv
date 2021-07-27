use curv::arithmetic::*;
use curv::elliptic::curves::*;

/// Pedersen Commitment:
/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
/// TO RUN:
/// cargo run --example pedersen_commitment -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example pedersen_commitment -- ristretto
///
/// notice: this library includes also hash based commitments

pub fn ped_com<E: Curve>(message: &BigInt) {
    use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
    use curv::cryptographic_primitives::commitments::traits::Commitment;

    let security_bits = 256;
    let blinding_factor = BigInt::sample(security_bits);
    let com = PedersenCommitment::<E>::create_commitment_with_user_defined_randomness(
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
    let message_bn = BigInt::from_bytes(message.as_bytes());
    let curve_name = std::env::args().nth(1);
    match curve_name.as_deref() {
        Some("secp256k1") => ped_com::<Secp256k1>(&message_bn),
        Some("ristretto") => ped_com::<Ristretto>(&message_bn),
        Some("ed25519") => ped_com::<Ed25519>(&message_bn),
        Some("bls12_381_1") => ped_com::<Bls12_381_1>(&message_bn),
        Some("bls12_381_2") => ped_com::<Bls12_381_2>(&message_bn),
        Some("p256") => ped_com::<Secp256r1>(&message_bn),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
