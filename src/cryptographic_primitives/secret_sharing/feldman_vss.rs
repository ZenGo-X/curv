#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::convert::{TryFrom, TryInto};
use std::num::NonZeroU16;
use std::{fmt, ops};

use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::hashing::Digest;
use crate::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use crate::cryptographic_primitives::secret_sharing::Polynomial;
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::ErrorSS::{self, VerifyShareError};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShamirSecretSharing {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43
///
/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
///
/// The scheme is augmented with a dlog proof for the constant commitment to protect against n-t+1 attack
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifiableSS<E: Curve, H: Digest + Clone> {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<Point<E>>,
    pub proof: DLogProof<E, H>,
}

/// Shared secret produced by [VerifiableSS::share]
///
/// After you shared your secret, you need to distribute `shares` among other parties, and erase
/// secret from your memory (SharedSecret zeroizes on drop).
///
/// You can retrieve a [polynomial](Self::polynomial) that was used to derive secret shares. It is
/// only needed to combine with other proofs (e.g. [low degree exponent interpolation]).
///
/// [low degree exponent interpolation]: crate::cryptographic_primitives::proofs::low_degree_exponent_interpolation
#[derive(Clone)]
pub struct SecretShares<E: Curve> {
    shares: Vec<Scalar<E>>,
    polynomial: Polynomial<E>,
}

impl<E: Curve, H: Digest + Clone> VerifiableSS<E, H> {
    pub fn reconstruct_limit(&self) -> u16 {
        self.parameters.threshold + 1
    }

    // generate VerifiableSS from a secret
    pub fn share(t: u16, n: u16, secret: &Scalar<E>) -> (VerifiableSS<E, H>, SecretShares<E>) {
        assert!(t < n);
        let polynomial = Polynomial::<E>::sample_exact_with_fixed_const_term(t, secret.clone());
        let shares = polynomial.evaluate_many_bigint(1..=n).collect();

        let g = Point::<E>::generator();
        let commitments = polynomial
            .coefficients()
            .iter()
            .map(|coef| g * coef)
            .collect::<Vec<_>>();

        let proof = DLogProof::<E, H>::prove(secret);
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
                proof,
            },
            SecretShares { shares, polynomial },
        )
    }

    // takes given VSS and generates a new VSS for the same secret and a secret shares vector to match the new commitments
    pub fn reshare(&self) -> (VerifiableSS<E, H>, Vec<Scalar<E>>) {
        let t = self.parameters.threshold;
        let n = self.parameters.share_count;

        let one = Scalar::<E>::from(1);
        let poly = Polynomial::<E>::sample_exact_with_fixed_const_term(t, one.clone());
        let secret_shares_biased: Vec<_> = poly.evaluate_many_bigint(1..=n).collect();
        let secret_shares: Vec<_> = (0..secret_shares_biased.len())
            .map(|i| &secret_shares_biased[i] - &one)
            .collect();
        let g = Point::<E>::generator();
        let mut new_commitments = vec![self.commitments[0].clone()];
        for (poly, commitment) in poly.coefficients().iter().zip(&self.commitments).skip(1) {
            new_commitments.push((g * poly) + commitment)
        }
        (
            VerifiableSS {
                parameters: self.parameters.clone(),
                commitments: new_commitments,
                proof: self.proof.clone(),
            },
            secret_shares,
        )
    }

    /// generate VerifiableSS from a secret and user defined x values (in case user wants to distribute point f(1), f(4), f(6) and not f(1),f(2),f(3))
    /// NOTE: The caller should make sure that `t`, `n` and the contents of `index_vec` can't be controlled by a malicious party.
    pub fn share_at_indices<I>(
        t: u16,
        n: u16,
        secret: &Scalar<E>,
        indicies: I,
    ) -> (VerifiableSS<E, H>, SecretShares<E>)
    where
        I: IntoIterator<Item = NonZeroU16>,
        I::IntoIter: ExactSizeIterator,
    {
        let indicies = indicies.into_iter();
        assert_eq!(usize::from(n), indicies.len());

        let polynomial = Polynomial::<E>::sample_exact_with_fixed_const_term(t, secret.clone());
        let shares = polynomial
            .evaluate_many_bigint(indicies.map(NonZeroU16::get))
            .collect();

        let g = Point::<E>::generator();
        let commitments = polynomial
            .coefficients()
            .iter()
            .map(|coef| g * coef)
            .collect::<Vec<Point<E>>>();

        let proof = DLogProof::<E, H>::prove(secret);
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
                proof,
            },
            SecretShares { shares, polynomial },
        )
    }

    // returns vector of coefficients
    #[deprecated(since = "0.8.0", note = "please use Polynomial::sample instead")]
    pub fn sample_polynomial(t: usize, coef0: &Scalar<E>) -> Vec<Scalar<E>> {
        Polynomial::<E>::sample_exact_with_fixed_const_term(t.try_into().unwrap(), coef0.clone())
            .coefficients()
            .to_vec()
    }

    #[deprecated(
        since = "0.8.0",
        note = "please use Polynomial::evaluate_many_bigint instead"
    )]
    pub fn evaluate_polynomial(coefficients: &[Scalar<E>], index_vec: &[usize]) -> Vec<Scalar<E>> {
        Polynomial::<E>::from_coefficients(coefficients.to_vec())
            .evaluate_many_bigint(index_vec.iter().map(|&i| u64::try_from(i).unwrap()))
            .collect()
    }

    #[deprecated(since = "0.8.0", note = "please use Polynomial::evaluate instead")]
    pub fn mod_evaluate_polynomial(coefficients: &[Scalar<E>], point: Scalar<E>) -> Scalar<E> {
        Polynomial::<E>::from_coefficients(coefficients.to_vec()).evaluate(&point)
    }

    pub fn reconstruct(&self, indices: &[u16], shares: &[Scalar<E>]) -> Scalar<E> {
        assert_eq!(shares.len(), indices.len());
        assert!(shares.len() >= usize::from(self.reconstruct_limit()));
        // add one to indices to get points
        let points = indices
            .iter()
            .map(|i| Scalar::from(*i + 1))
            .collect::<Vec<_>>();
        VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, shares)
    }

    // Performs a Lagrange interpolation in field Zp at the origin
    // for a polynomial defined by `points` and `values`.
    // `points` and `values` are expected to be two arrays of the same size, containing
    // respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).

    // The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.

    // This is obviously less general than `newton_interpolation_general` as we
    // only get a single value, but it is much faster.

    pub fn lagrange_interpolation_at_zero(points: &[Scalar<E>], values: &[Scalar<E>]) -> Scalar<E> {
        let vec_len = values.len();

        assert_eq!(points.len(), vec_len);
        // Lagrange interpolation for point 0
        // let mut acc = 0i64;
        let lag_coef =
            (0..vec_len)
                .map(|i| {
                    let xi = &points[i];
                    let yi = &values[i];
                    let num = Scalar::from(1);
                    let denum = Scalar::from(1);
                    let num = points.iter().zip(0..vec_len).fold(num, |acc, x| {
                        if i != x.1 {
                            acc * x.0
                        } else {
                            acc
                        }
                    });
                    let denum = points.iter().zip(0..vec_len).fold(denum, |acc, x| {
                        if i != x.1 {
                            let xj_sub_xi = x.0 - xi;
                            acc * xj_sub_xi
                        } else {
                            acc
                        }
                    });
                    let denum = denum.invert().unwrap();
                    num * denum * yi
                })
                .collect::<Vec<_>>();
        let mut lag_coef_iter = lag_coef.iter();
        let head = lag_coef_iter.next().unwrap();
        let tail = lag_coef_iter;
        tail.fold(head.clone(), |acc, x| acc + x)
    }

    pub fn validate_share(&self, secret_share: &Scalar<E>, index: u16) -> Result<(), ErrorSS> {
        if self.commitments[0] != self.proof.pk || DLogProof::verify(&self.proof).is_err() {
            return Err(VerifyShareError);
        }
        let g = Point::generator();
        let ss_point = g * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(&self, ss_point: &Point<E>, index: u16) -> Result<(), ErrorSS> {
        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }

    pub fn get_point_commitment(&self, index: u16) -> Point<E> {
        let index_fe = Scalar::from(index);
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        tail.fold(head.clone(), |acc, x| x + acc * &index_fe)
    }

    //compute \lambda_{index,S}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|)
    // used in http://stevengoldfeder.com/papers/GG18.pdf
    pub fn map_share_to_new_params(
        _params: &ShamirSecretSharing,
        index: u16,
        s: &[u16],
    ) -> Scalar<E> {
        let j = (0u16..)
            .zip(s)
            .find_map(|(j, s_j)| if *s_j == index { Some(j) } else { None })
            .expect("`s` doesn't include `index`");
        let xs = s.iter().map(|x| Scalar::from(*x + 1)).collect::<Vec<_>>();
        Polynomial::lagrange_basis(&Scalar::zero(), j, &xs)
    }
}

impl<E: Curve> SecretShares<E> {
    /// Polynomial that was used to derive secret shares
    pub fn polynomial(&self) -> &Polynomial<E> {
        &self.polynomial
    }
}

impl<E: Curve> fmt::Debug for SecretShares<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // blind sensitive data stored by the structure
        write!(f, "SecretShares{{ ... }}")
    }
}

impl<E: Curve> ops::Deref for SecretShares<E> {
    type Target = [Scalar<E>];
    fn deref(&self) -> &Self::Target {
        &self.shares
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_for_all_curves_and_hashes;

    test_for_all_curves_and_hashes!(test_secret_sharing_3_out_of_5_at_indices);

    fn test_secret_sharing_3_out_of_5_at_indices<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();
        let parties = [1, 2, 4, 5, 6];
        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share_at_indices(
            3,
            5,
            &secret,
            parties.iter().map(|&v| NonZeroU16::new(v).unwrap()),
        );

        let shares_vec = vec![
            secret_shares[0].clone(),
            secret_shares[1].clone(),
            secret_shares[3].clone(),
            secret_shares[4].clone(),
        ];

        //test reconstruction

        let secret_reconstructed = vss_scheme.reconstruct(&[0, 1, 4, 5], &shares_vec);
        assert_eq!(secret, secret_reconstructed);
    }

    test_for_all_curves_and_hashes!(test_secret_sharing_3_out_of_5);

    fn test_secret_sharing_3_out_of_5<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();

        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share(3, 5, &secret);

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

        let g = Point::generator();
        let share1_public = g * &secret_shares[0];
        let valid1_public = vss_scheme.validate_share_public(&share1_public, 1);
        assert!(valid1_public.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1, 2, 3, 4];
        let l0 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 0, s);
        let l1 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 1, s);
        let l2 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 2, s);
        let l3 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 3, s);
        let l4 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 4, s);
        let w = l0 * &secret_shares[0]
            + l1 * &secret_shares[1]
            + l2 * &secret_shares[2]
            + l3 * &secret_shares[3]
            + l4 * &secret_shares[4];
        assert_eq!(w, secret_reconstructed);
    }

    test_for_all_curves_and_hashes!(test_secret_sharing_3_out_of_7);

    fn test_secret_sharing_3_out_of_7<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();

        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share(3, 7, &secret);

        let shares_vec = vec![
            secret_shares[0].clone(),
            secret_shares[6].clone(),
            secret_shares[2].clone(),
            secret_shares[4].clone(),
        ];

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&[0, 6, 2, 4], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid3.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1, 3, 4, 6];
        let l0 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 0, s);
        let l1 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 1, s);
        let l3 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 3, s);
        let l4 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 4, s);
        let l6 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 6, s);

        let w = l0 * &secret_shares[0]
            + l1 * &secret_shares[1]
            + l3 * &secret_shares[3]
            + l4 * &secret_shares[4]
            + l6 * &secret_shares[6];
        assert_eq!(w, secret_reconstructed);
    }

    test_for_all_curves_and_hashes!(test_secret_sharing_1_out_of_2);

    fn test_secret_sharing_1_out_of_2<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();

        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share(1, 2, &secret);

        let shares_vec = vec![secret_shares[0].clone(), secret_shares[1].clone()];

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&[0, 1], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid2 = vss_scheme.validate_share(&secret_shares[1], 2);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid2.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1];
        let l0 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 0, s);
        let l1 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 1, s);
        let w = l0 * &secret_shares[0] + l1 * &secret_shares[1];
        assert_eq!(w, secret_reconstructed);
    }

    test_for_all_curves_and_hashes!(test_secret_sharing_1_out_of_3);

    fn test_secret_sharing_1_out_of_3<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();

        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share(1, 3, &secret);

        let shares_vec = vec![secret_shares[0].clone(), secret_shares[1].clone()];

        // test commitment to point and sum of commitments
        let (vss_scheme2, secret_shares2) = VerifiableSS::<E, H>::share(1, 3, &secret);
        let sum = &secret_shares[0] + &secret_shares2[0];
        let point_comm1 = vss_scheme.get_point_commitment(1);
        let point_comm2 = vss_scheme.get_point_commitment(2);
        let g = Point::generator();
        let g_sum = g * sum;
        assert_eq!(g * &secret_shares[0], point_comm1);
        assert_eq!(g * &secret_shares[1], point_comm2);
        let point1_sum_com =
            vss_scheme.get_point_commitment(1) + vss_scheme2.get_point_commitment(1);
        assert_eq!(point1_sum_com, g_sum);

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&[0, 1], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid2 = vss_scheme.validate_share(&secret_shares[1], 2);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid2.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 2];
        let l0 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 0, s);
        let l2 = VerifiableSS::<E, H>::map_share_to_new_params(&vss_scheme.parameters, 2, s);

        let w = l0 * &secret_shares[0] + l2 * &secret_shares[2];
        assert_eq!(w, secret_reconstructed);
    }

    test_for_all_curves_and_hashes!(test_secret_resharing);

    fn test_secret_resharing<E: Curve, H: Digest + Clone>() {
        let secret = Scalar::random();

        let (vss_scheme, secret_shares) = VerifiableSS::<E, H>::share(1, 3, &secret);
        let (new_vss_scheme, zero_secret_shares) = vss_scheme.reshare();

        let new_share_party_1 = &secret_shares[0] + &zero_secret_shares[0];
        let new_share_party_2 = &secret_shares[1] + &zero_secret_shares[1];
        let new_share_party_3 = &secret_shares[2] + &zero_secret_shares[2];

        let shares_vec = vec![new_share_party_1.clone(), new_share_party_3.clone()];

        // reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&[0, 2], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid1 = new_vss_scheme.validate_share(&new_share_party_1, 1);
        let valid2 = new_vss_scheme.validate_share(&new_share_party_2, 2);
        let valid3 = new_vss_scheme.validate_share(&new_share_party_3, 3);

        assert!(valid1.is_ok());
        assert!(valid2.is_ok());
        assert!(valid3.is_ok());
    }
}
