use curv::BigInt;

/// Pedesen Commitment:
/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
/// TO RUN:
/// cargo run --example pedersen_commitment --features CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example pedersen_commitment --features ec_ristretto
///
/// notice: this library includes also hash based commitments

#[cfg(feature = "ecc")]
pub fn ped_com(message: &BigInt) {
    use curv::arithmetic::traits::Samplable;
    use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
    use curv::cryptographic_primitives::commitments::traits::Commitment;

    let security_bits = 256;
    let blinding_factor = BigInt::sample(security_bits);
    let com = PedersenCommitment::create_commitment_with_user_defined_randomness(
        message,
        &blinding_factor,
    );
    (com, blinding_factor);
}

fn main() {
    let message = "commit me!";
    let message_bytes = message.as_bytes();
    let message_bn = BigInt::from(message_bytes);
    #[cfg(feature = "ecc")]
    ped_com(&message_bn);
}
