pub mod g1;
pub mod g2;

use crate::elliptic::curves::bls12_381::g1::GE as GE1;
use crate::elliptic::curves::bls12_381::g2::GE as GE2;
use crate::elliptic::curves::traits::ECPoint;
use ff::Field;
use pairing_plus::bls12_381::{Bls12, Fq12};
use pairing_plus::{CurveAffine, Engine};

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Pair {
    pub e: Fq12,
}

impl Pair {
    pub fn compute_pairing(g1_ge: &GE1, g2_ge: &GE2) -> Self {
        Pair {
            e: g1_ge.get_element().pairing_with(&g2_ge.get_element()),
        }
    }

    /// Efficiently computes product of pairings.
    ///
    /// Computes `e(g1,g2) * e(g3,g4)` with a single final exponentiation.
    ///
    /// ## Panic
    /// Method panics if miller_loop of product is equal to zero.
    pub fn efficient_pairing_mul(g1: &GE1, g2: &GE2, g3: &GE1, g4: &GE2) -> Self {
        Pair {
            e: Bls12::final_exponentiation(&Bls12::miller_loop(
                [
                    (&(g1.get_element().prepare()), &(g2.get_element().prepare())),
                    (&(g3.get_element().prepare()), &(g4.get_element().prepare())),
                ]
                .iter(),
            ))
            .unwrap(),
        }
    }

    pub fn add_pair(&self, other: &Pair) -> Self {
        let mut res = self.clone();
        res.e.mul_assign(&other.e);
        Pair { e: res.e }
    }
}

#[cfg(test)]
mod tests {
    use super::Pair;
    use crate::elliptic::curves::bls12_381::g1::FE;
    use crate::elliptic::curves::bls12_381::g1::GE as GE1;
    use crate::elliptic::curves::bls12_381::g2::GE as GE2;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;

    #[test]
    fn powers_of_g1_and_g2() {
        let a: GE1 = ECPoint::generator();
        let b: GE2 = ECPoint::generator();
        let scalar_factor: FE = ECScalar::new_random();
        let res_mul_a = a.scalar_mul(&scalar_factor.get_element());
        let res_mul_b = b.scalar_mul(&scalar_factor.get_element());
        let res_a_power = Pair::compute_pairing(&res_mul_a, &b);
        let res_b_power = Pair::compute_pairing(&a, &res_mul_b);
        assert_eq!(res_a_power, res_b_power);
    }

    // e(P,Q)e(P,R) = e(P, Q+ R)
    #[test]
    fn pairing() {
        let p: GE1 = ECPoint::generator();
        let q: GE2 = ECPoint::generator();
        let r: GE2 = ECPoint::base_point2();
        let q_plus_r = &q + &r;
        let e_p_q = Pair::compute_pairing(&p, &q);
        let e_p_r = Pair::compute_pairing(&p, &r);
        let e_p_q_r = Pair::compute_pairing(&p, &q_plus_r);
        let e_p_q_add_e_p_r = e_p_q.add_pair(&e_p_r);
        assert_eq!(e_p_q_add_e_p_r, e_p_q_r);
    }
}
