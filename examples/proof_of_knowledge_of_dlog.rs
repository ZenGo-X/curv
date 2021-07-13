use curv::elliptic::curves::*;

/// Sigma protocol for proof of knowledge of discrete log
/// TO RUN:
/// cargo run --example proof_of_knowledge_of_dlog -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example proof_of_knowledge_of_dlog -- jubjub
///
/// notice: this library includes other more complex sigma protocol.
/// see proofs folder for more details

pub fn dlog_proof<E: Curve>() {
    use curv::cryptographic_primitives::proofs::sigma_dlog::*;

    let witness = Scalar::random();
    let dlog_proof = DLogProof::<E>::prove(&witness);
    assert!(DLogProof::verify(&dlog_proof).is_ok());
}

fn main() {
    let curve_name = std::env::args().nth(1);
    match curve_name.as_deref() {
        Some("secp256k1") => dlog_proof::<Secp256k1>(),
        // Some("ristretto") => dlog_proof::<curv::elliptic::curves::curve_ristretto::GE>(),
        // Some("ed25519") => dlog_proof::<curv::elliptic::curves::ed25519::GE>(),
        // Some("bls12_381") => dlog_proof::<curv::elliptic::curves::bls12_381::g1::GE>(),
        // Some("p256") => dlog_proof::<curv::elliptic::curves::p256::GE>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
