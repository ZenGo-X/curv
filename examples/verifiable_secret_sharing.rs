/// secret_sharing_3_out_of_5
/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43

/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
/// TO RUN:
/// cargo run --example verifiable_secret_sharing --features CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example verifiable_secret_sharing --features ec_ed25519

#[cfg(feature = "ecc")]
pub fn secret_sharing_3_out_of_5() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};

    let secret: FE = ECScalar::new_random();

    let (vss_scheme, secret_shares) = VerifiableSS::share(3, 5, &secret);

    let mut shares_vec = Vec::new();
    shares_vec.push(secret_shares[0].clone());
    shares_vec.push(secret_shares[1].clone());
    shares_vec.push(secret_shares[2].clone());
    shares_vec.push(secret_shares[4].clone());
    //test reconstruction

    let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1, 2, 4], &shares_vec);

    assert_eq!(secret, secret_reconstructed);
    // test secret shares are verifiable
    let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
    let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
    assert!(valid3.is_ok());
    assert!(valid1.is_ok());

    let g: GE = GE::generator();
    let share1_public = g * &secret_shares[0];
    let valid1_public = vss_scheme.validate_share_public(&share1_public, 1);
    assert!(valid1_public.is_ok());

    // test map (t,n) - (t',t')
    let s = &vec![0, 1, 2, 3, 4];
    let l0 = vss_scheme.map_share_to_new_params(0, &s);
    let l1 = vss_scheme.map_share_to_new_params(1, &s);
    let l2 = vss_scheme.map_share_to_new_params(2, &s);
    let l3 = vss_scheme.map_share_to_new_params(3, &s);
    let l4 = vss_scheme.map_share_to_new_params(4, &s);
    let w = l0 * secret_shares[0].clone()
        + l1 * secret_shares[1].clone()
        + l2 * secret_shares[2].clone()
        + l3 * secret_shares[3].clone()
        + l4 * secret_shares[4].clone();
    assert_eq!(w, secret_reconstructed);
}

fn main() {
    #[cfg(feature = "ecc")]
    secret_sharing_3_out_of_5();
}
