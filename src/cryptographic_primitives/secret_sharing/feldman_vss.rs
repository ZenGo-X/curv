/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43

use elliptic::curves::traits::*;
use BigInt;
use ErrorSS::{self, VerifyShareError};
use FE;
use GE;

#[derive(Clone, PartialEq, Debug)]
pub struct ShamirSecretSharing {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}
#[derive(Clone, PartialEq, Debug)]
pub struct VerifiableSS {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<GE>,
}

impl VerifiableSS {
    pub fn reconstruct_limit(&self) -> usize {
        self.parameters.threshold + 1
    }

    // generate VerifiableSS from a secret
    pub fn share(t: usize, n: usize, secret: &FE) -> (VerifiableSS, Vec<FE>) {
        let poly = VerifiableSS::sample_polynomial(t.clone(), secret);
        let secret_shares = VerifiableSS::evaluate_polynomial(n.clone(), &poly);
        let G: GE = ECPoint::generator();
        let commitments = (0..poly.len())
            .map(|i| G.clone() * &poly[i])
            .collect::<Vec<GE>>();
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t.clone(),
                    share_count: n.clone(),
                },
                commitments,
            },
            secret_shares,
        )
    }

    // returns vector of coefficients
    pub fn sample_polynomial(t: usize, coef0: &FE) -> Vec<FE> {
        let mut coefficients = vec![coef0.clone()];
        // sample the remaining coefficients randomly using secure randomness
        let random_coefficients: Vec<FE> = (0..t).map(|_| ECScalar::new_random()).collect();
        coefficients.extend(random_coefficients);
        // return
        coefficients
    }

    pub fn evaluate_polynomial(n: usize, coefficients: &[FE]) -> Vec<FE> {
        (1..n + 1)
            .map(|point| {
                let point_bn = BigInt::from(point as u32);
                VerifiableSS::mod_evaluate_polynomial(coefficients, ECScalar::from(&point_bn))
            }).collect::<Vec<FE>>()
    }

    pub fn mod_evaluate_polynomial(coefficients: &[FE], point: FE) -> FE {
        // evaluate using Horner's rule
        //  - to combine with fold we consider the coefficients in reverse order
        let mut reversed_coefficients = coefficients.iter().rev();
        // manually split due to fold insisting on an initial value
        let head = reversed_coefficients.next().unwrap();
        let tail = reversed_coefficients;
        tail.fold(head.clone(), |partial, coef| {
            let partial_times_point = partial.mul(&point.get_element());
            partial_times_point.add(&coef.get_element())
        })
    }

    pub fn reconstruct(&self, indices: &[usize], shares: &[FE]) -> FE {
        assert_eq!(shares.len(), indices.len());
        assert!(shares.len() >= self.reconstruct_limit());
        // add one to indices to get points
        let points: Vec<FE> = indices
            .iter()
            .map(|i| {
                let index_bn = BigInt::from(i.clone() as u32 + 1 as u32);
                ECScalar::from(&index_bn)
            }).collect::<Vec<FE>>();
        VerifiableSS::lagrange_interpolation_at_zero(&points, &shares)
    }

    // Performs a Lagrange interpolation in field Zp at the origin
    // for a polynomial defined by `points` and `values`.
    // `points` and `values` are expected to be two arrays of the same size, containing
    // respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).

    // The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.

    // This is obviously less general than `newton_interpolation_general` as we
    // only get a single value, but it is much faster.

    pub fn lagrange_interpolation_at_zero(points: &[FE], values: &[FE]) -> FE {
        let vec_len = values.len();

        assert_eq!(points.len(), vec_len);
        // Lagrange interpolation for point 0
        // let mut acc = 0i64;
        let lag_coef = (0..vec_len)
            .map(|i| {
                let xi = &points[i];
                let yi = &values[i];
                let mut num: FE = ECScalar::from(&BigInt::one());
                let mut denum: FE = ECScalar::from(&BigInt::one());
                let num = points.iter().zip((0..vec_len)).fold(num, |acc, x| {
                    if i != x.1 {
                        acc * x.0
                    } else {
                        acc
                    }
                });
                let denum = points.iter().zip((0..vec_len)).fold(denum, |acc, x| {
                    if i != x.1 {
                        let xj_sub_xi = x.0.sub(&xi.get_element());
                        acc * xj_sub_xi
                    } else {
                        acc
                    }
                });
                let denum = denum.invert();
                num * denum * yi
            }).collect::<Vec<FE>>();
        let mut lag_coef_iter = lag_coef.iter();
        let head = lag_coef_iter.next().unwrap();
        let tail = lag_coef_iter;
        let result = tail.fold(head.clone(), |acc, x| acc.add(&x.get_element()));
        result
    }

    pub fn validate_share(&self, secret_share: &FE, index: &usize) -> Result<(), (ErrorSS)> {
        let G: GE = ECPoint::generator();
        let index_fe: FE = ECScalar::from(&BigInt::from(index.clone() as u32));
        let ss_point = G.clone() * secret_share;
        //  let comm_vec = &self.commitments.clone();
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        let comm_to_point = tail.fold(head.clone(), |acc, x: &GE| x.clone() + acc * &index_fe);
        if ss_point.get_element() == comm_to_point.get_element() {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::secret_sharing::feldman_vss::*;
    use elliptic::curves::traits::*;
    use {FE, GE};

    #[test]
    fn test_secret_sharing_3_out_of_5() {
        let secret: FE = ECScalar::new_random();
        let (vss_scheme, secret_shares) = VerifiableSS::share(3, 5, &secret);
        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[1].clone());
        shares_vec.push(secret_shares[2].clone());
        shares_vec.push(secret_shares[4].clone());
        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1, 2, 4], &shares_vec);
        let valid3 = vss_scheme.validate_share(&secret_shares[2], &3);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], &1);
        assert_eq!(secret.get_element(), secret_reconstructed.get_element());
        assert!(valid3.is_ok());
        assert!(valid1.is_ok());
    }
}
