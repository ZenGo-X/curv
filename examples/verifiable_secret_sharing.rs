use std::fmt::Debug;

use curv::elliptic::curves::traits::ECPoint;

/// secret_sharing_3_out_of_5
/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43

/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
/// TO RUN:
/// cargo run --example verifiable_secret_sharing -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example verifiable_secret_sharing -- ed25519

pub fn secret_sharing_3_out_of_5<P>()
where
    P: ECPoint + Clone,
    P::Scalar: PartialEq + Clone + Debug,
{
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::traits::ECScalar;

    let secret: P::Scalar = ECScalar::new_random();

    let (vss_scheme, secret_shares) = VerifiableSS::<P>::share(3, 5, &secret);

    let shares_vec = vec![
        secret_shares[0].clone(),
        secret_shares[1].clone(),
        secret_shares[2].clone(),
        secret_shares[4].clone(),
    ];
    //test reconstruction

    let secret_reconstructed = vss_scheme.reconstruct(&[0, 1, 2, 4], &shares_vec);

    assert_eq!(secret, secret_reconstructed);
    // test secret shares are verifiable
    let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
    let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
    assert!(valid3.is_ok());
    assert!(valid1.is_ok());

    let g: P = ECPoint::generator();
    let share1_public = g * secret_shares[0].clone();
    let valid1_public = vss_scheme.validate_share_public(&share1_public, 1);
    assert!(valid1_public.is_ok());

    // test map (t,n) - (t',t')
    let s = &vec![0, 1, 2, 3, 4];
    let l0 = VerifiableSS::<P>::map_share_to_new_params(&vss_scheme.parameters, 0, &s);
    let l1 = VerifiableSS::<P>::map_share_to_new_params(&vss_scheme.parameters, 1, &s);
    let l2 = VerifiableSS::<P>::map_share_to_new_params(&vss_scheme.parameters, 2, &s);
    let l3 = VerifiableSS::<P>::map_share_to_new_params(&vss_scheme.parameters, 3, &s);
    let l4 = VerifiableSS::<P>::map_share_to_new_params(&vss_scheme.parameters, 4, &s);

    let w = l0 * secret_shares[0].clone()
        + l1 * secret_shares[1].clone()
        + l2 * secret_shares[2].clone()
        + l3 * secret_shares[3].clone()
        + l4 * secret_shares[4].clone();
    assert_eq!(w, secret_reconstructed);
}

fn main() {
    let curve_name = std::env::args().nth(1);
    match curve_name.as_ref().map(|s| s.as_str()) {
        Some("secp256k1") => secret_sharing_3_out_of_5::<curv::elliptic::curves::secp256_k1::GE>(),
        Some("ristretto") => {
            secret_sharing_3_out_of_5::<curv::elliptic::curves::curve_ristretto::GE>()
        }
        Some("ed25519") => secret_sharing_3_out_of_5::<curv::elliptic::curves::ed25519::GE>(),
        Some("bls12_381") => {
            secret_sharing_3_out_of_5::<curv::elliptic::curves::bls12_381::g1::GE>()
        }
        Some("p256") => secret_sharing_3_out_of_5::<curv::elliptic::curves::p256::GE>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}
