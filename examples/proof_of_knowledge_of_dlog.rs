use curv::elliptic::curves::traits::ECPoint;
use zeroize::Zeroize;

/// Sigma protocol for proof of knowledge of discrete log
/// TO RUN:
/// cargo run --example proof_of_knowledge_of_dlog -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example proof_of_knowledge_of_dlog -- jubjub
///
/// notice: this library includes other more complex sigma protocol.
/// see proofs folder for more details

pub fn dlog_proof<P>()
where
    P: ECPoint + Clone,
    P::Scalar: Zeroize,
{
    use curv::cryptographic_primitives::proofs::sigma_dlog::*;
    use curv::elliptic::curves::traits::ECScalar;

    let witness: P::Scalar = ECScalar::new_random();
    let dlog_proof = DLogProof::<P>::prove(&witness);
    let verified = DLogProof::verify(&dlog_proof);
    match verified {
        Ok(_t) => assert!(true),
        Err(_e) => assert!(false),
    }
}

fn main() {
    let curve_name = std::env::args().nth(1);
    match curve_name.as_ref().map(|s| s.as_str()) {
        Some("secp256k1") => dlog_proof::<curv::elliptic::curves::secp256_k1::GE>(),
        Some("ristretto") => dlog_proof::<curv::elliptic::curves::curve_ristretto::GE>(),
        Some("ed25519") => dlog_proof::<curv::elliptic::curves::ed25519::GE>(),
        Some("bls12_381") => dlog_proof::<curv::elliptic::curves::bls12_381::GE>(),
        Some("p256") => dlog_proof::<curv::elliptic::curves::p256::GE>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
