pub use super::traits::Pairing;
use crate::elliptic::curves::bls12_381::g1;
use crate::elliptic::curves::bls12_381::g2;
pub use crate::elliptic::curves::traits::*;
use bls12_381::pairing;
use bls12_381::Gt;

#[allow(dead_code)]
type FE1 = g1::FE;
type GE1 = g1::GE;

#[allow(dead_code)]
type FE2 = g2::FE;
type GE2 = g2::GE;

pub struct PAIRING;

impl<'a> Pairing<GE1, GE2, Gt> for PAIRING {
    fn compute_pairing(g1: &GE1, g2: &GE2) -> Gt {
        pairing(&g1.get_element(), &g2.get_element())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn powers_of_g1_and_g2() {
        let a: GE1 = ECPoint::generator();
        let b: GE2 = ECPoint::generator();
        let scalar_factor: FE1 = ECScalar::new_random();
        let res_mul_a: GE1 = a.scalar_mul(&scalar_factor.get_element());
        let res_mul_b: GE2 = b.scalar_mul(&scalar_factor.get_element());
        let res_a_power = PAIRING::compute_pairing(&res_mul_a, &b);
        let res_b_power = PAIRING::compute_pairing(&a, &res_mul_b);
        assert_eq!(res_a_power, res_b_power);
    }

    #[test]
    fn powers_of_g1_and_gt_eq() {
        let a: GE1 = ECPoint::generator();
        let b: GE2 = ECPoint::generator();
        let scalar_factor: FE1 = ECScalar::new_random();
        let res_mul_a: GE1 = a.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = PAIRING::compute_pairing(&res_mul_a, &b);
        let gt_direct_power = PAIRING::compute_pairing(&a, &b) * scalar_factor.get_element();
        assert_eq!(gt_direct_power, gt_from_a_power);
    }


    #[test]
    fn powers_of_g2_and_gt_eq() {
        let a: GE1 = ECPoint::generator();
        let b: GE2 = ECPoint::generator();
        let scalar_factor: FE1 = ECScalar::new_random();
        let res_mul_b: GE2 = b.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = PAIRING::compute_pairing(&a, &res_mul_b);
        let gt_direct_power = PAIRING::compute_pairing(&a, &b) * scalar_factor.get_element();
        assert_eq!(gt_direct_power, gt_from_a_power);
    }
}
