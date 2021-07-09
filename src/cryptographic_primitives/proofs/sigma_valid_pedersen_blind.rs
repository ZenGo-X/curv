/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use serde::{Deserialize, Serialize};

use super::ProofError;
use crate::arithmetic::Converter;
use crate::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use crate::cryptographic_primitives::commitments::traits::Commitment;
use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::{Curve, Point, PointZ, Scalar, ScalarZ};
use crate::BigInt;

/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (r) such that c = mG + rH.
/// witness: (r), statement: (c,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses A = s*H for random s
/// prover calculates challenge e = H(G,H,c,A,m)
/// prover calculates z  = s + er,
/// prover sends pi = {e, m,A,c, z}
/// verifier checks that emG + zH  = A + ec
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PedersenBlindingProof<E: Curve> {
    e: ScalarZ<E>,
    pub m: Scalar<E>,
    a: Point<E>,
    pub com: PointZ<E>,
    z: ScalarZ<E>,
}

impl<E: Curve> PedersenBlindingProof<E> {
    #[allow(clippy::many_single_char_names)]
    //TODO: add self verification to prover proof
    pub fn prove(m: &Scalar<E>, r: &Scalar<E>) -> PedersenBlindingProof<E> {
        let h = Point::<E>::base_point2();
        let s = Scalar::<E>::random();
        let a = h * &s;
        let com: PointZ<E> = PedersenCommitment::create_commitment_with_user_defined_randomness(
            &m.to_bigint(),
            &r.to_bigint(),
        );
        let g = Point::<E>::generator();
        let challenge = HSha256::create_hash(&[
            &BigInt::from_bytes(&g.as_point().to_bytes(true)),
            &BigInt::from_bytes(&h.to_bytes(true)),
            &com.to_bytes(true)
                .map(|b| BigInt::from_bytes(&b))
                .unwrap_or_else(|| BigInt::from_bytes(b"infinity point")),
            &BigInt::from_bytes(&a.to_bytes(true)),
            &m.to_bigint(),
        ]);
        let e = ScalarZ::from(&challenge);

        let er = &e * r;
        let z = &s + &er;
        PedersenBlindingProof {
            e,
            m: m.clone(),
            a,
            com,
            z,
        }
    }

    pub fn verify(proof: &PedersenBlindingProof<E>) -> Result<(), ProofError> {
        let g = Point::<E>::generator();
        let h = Point::<E>::base_point2();
        let challenge = HSha256::create_hash(&[
            &BigInt::from_bytes(&g.as_point().to_bytes(true)),
            &BigInt::from_bytes(&h.to_bytes(true)),
            &proof
                .com
                .to_bytes(true)
                .map(|b| BigInt::from_bytes(&b))
                .unwrap_or_else(|| BigInt::from_bytes(b"infinity point")),
            &BigInt::from_bytes(&proof.a.to_bytes(true)),
            &proof.m.to_bigint(),
        ]);

        let e = ScalarZ::from(&challenge);

        let zh = h * &proof.z;
        let mg = g * &proof.m;
        let emg = mg * &e;
        let lhs = zh + emg;
        let ecom = &proof.com * &e;
        let rhs = ecom + &proof.a;

        if lhs == rhs {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves!(test_pedersen_blind_proof);
    fn test_pedersen_blind_proof<E: Curve>() {
        let m = Scalar::random();
        let r = Scalar::random();
        let pedersen_proof = PedersenBlindingProof::<E>::prove(&m, &r);
        let _verified =
            PedersenBlindingProof::verify(&pedersen_proof).expect("error pedersen blind");
    }
}
