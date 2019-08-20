/// Sigma protocol for proof of knowledge of discrete log
/// TO RUN:
/// cargo run --example proof_of_knowledge_of_dlog --features CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example proof_of_knowledge_of_dlog --features ec_jubjub
///
/// notice: this library includes other more complex sigma protocol.
/// see proofs folder for more details

#[cfg(feature = "ecc")]
pub fn dlog_proof() {
    use curv::cryptographic_primitives::proofs::sigma_dlog::*;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;

    let witness: FE = ECScalar::new_random();
    let dlog_proof = DLogProof::prove(&witness);
    let verified = DLogProof::verify(&dlog_proof);
    match verified {
        Ok(_t) => assert!(true),
        Err(_e) => assert!(false),
    }
}

fn main() {
    #[cfg(feature = "ecc")]
    dlog_proof();
}
