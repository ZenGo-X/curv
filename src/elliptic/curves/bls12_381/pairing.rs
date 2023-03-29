use ff_zeroize::Field;
use pairing_plus::bls12_381::{Bls12, Fq12};
use pairing_plus::{CurveAffine, Engine};

use crate::elliptic::curves::bls12_381::{Bls12_381_1, Bls12_381_2};
use crate::elliptic::curves::traits::*;
use crate::elliptic::curves::Point;

/// Bilinear pairing function
///
/// _Note_: pairing function support is experimental and subject to change
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pair {
    pub e: Fq12,
}

impl Pair {
    /// Computes pairing `e(p1, p2)`
    pub fn compute_pairing(p1: &Point<Bls12_381_1>, p2: &Point<Bls12_381_2>) -> Self {
        Pair {
            e: p1
                .as_raw()
                .underlying_ref()
                .pairing_with(p2.as_raw().underlying_ref()),
        }
    }

    /// Efficiently computes product of pairings
    ///
    /// Computes `e(g1,g2) * e(g3,g4)` with a single final exponentiation.
    ///
    /// ## Panic
    /// Method panics if miller_loop of product is equal to zero.
    pub fn efficient_pairing_mul(
        p1: &Point<Bls12_381_1>,
        p2: &Point<Bls12_381_2>,
        p3: &Point<Bls12_381_1>,
        p4: &Point<Bls12_381_2>,
    ) -> Self {
        Pair {
            e: Bls12::final_exponentiation(&Bls12::miller_loop(
                [
                    (
                        &(p1.as_raw().underlying_ref().prepare()),
                        &(p2.as_raw().underlying_ref().prepare()),
                    ),
                    (
                        &(p3.as_raw().underlying_ref().prepare()),
                        &(p4.as_raw().underlying_ref().prepare()),
                    ),
                ]
                .iter(),
            ))
            .unwrap(),
        }
    }

    pub fn add_pair(&self, other: &Pair) -> Self {
        let mut res = *self;
        res.e.mul_assign(&other.e);
        Pair { e: res.e }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elliptic::curves::Scalar;

    #[test]
    fn powers_of_g1_and_g2() {
        let a = Point::<Bls12_381_1>::generator().to_point();
        let b = Point::<Bls12_381_2>::generator().to_point();
        let scalar_factor_1 = Scalar::<Bls12_381_1>::random();
        let scalar_factor_2 = Scalar::<Bls12_381_2>::from_raw(scalar_factor_1.as_raw().clone());
        let res_mul_a = &a * &scalar_factor_1;
        let res_mul_b = &b * &scalar_factor_2;
        let res_a_power = Pair::compute_pairing(&res_mul_a, &b);
        let res_b_power = Pair::compute_pairing(&a, &res_mul_b);
        assert_eq!(res_a_power, res_b_power);
    }

    // e(P,Q)e(P,R) = e(P, Q+ R)
    #[test]
    fn pairing() {
        let p = Point::<Bls12_381_1>::generator().to_point();
        let q = Point::<Bls12_381_2>::generator().to_point();
        let r = Point::<Bls12_381_2>::base_point2();
        let q_plus_r = &q + r;
        let e_p_q = Pair::compute_pairing(&p, &q);
        let e_p_r = Pair::compute_pairing(&p, r);
        let e_p_q_r = Pair::compute_pairing(&p, &q_plus_r);
        let e_p_q_add_e_p_r = e_p_q.add_pair(&e_p_r);
        assert_eq!(e_p_q_add_e_p_r, e_p_q_r);
    }
}
