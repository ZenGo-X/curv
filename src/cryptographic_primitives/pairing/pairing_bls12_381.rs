
pub use super::traits::Pairing;
use crate::elliptic::curves::bls12_381::g1;
use crate::elliptic::curves::bls12_381::g2;
use bls12_381::Gt;
use bls12_381::pairing;
use bls12_381::G2Prepared;
use bls12_381::multi_miller_loop;
pub use crate::elliptic::curves::traits::*;

type FE1 = g1::FE;
type GE1 = g1::GE;
type PK1 = g1::PK;
type SK1 = g1::SK;

type FE2 = g2::FE;
type GE2 = g2::GE;
type PK2 = g2::PK;
type SK2 = g2::SK;

pub struct bls_pairing;


impl <'a>Pairing<GE1,GE2,Gt> for bls_pairing{
    fn compute_pairing(g1:&GE1,g2:&GE2)->Gt {
        pairing(&g1.get_element(),&g2.get_element())
    }
}


#[cfg(test)]
mod tests{
    use super::*;
    use crate::BigInt;

    type FE1 = g1::FE;
    type GE1 = g1::GE;
    type PK1 = g1::PK;
    type SK1 = g1::SK;

    type FE2 = g2::FE;
    type GE2 = g2::GE;
    type PK2 = g2::PK;
    type SK2 = g2::SK;
    /*
    crate::elliptic::curves::bls12_381::g2;
    use bls12_381::Gt;
    use bls12_381::pairing;
    pub use crate::elliptic::curves::traits::ECPoint;
    use crate::cryptographic_primitives::pairing::pairing_bls12_381::GE1;
*/

    fn compute_pairing_for_debug(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let res = bls_pairing::compute_pairing(&a,&b);
        println!("pairing result {:?}", res);
    }

    #[test]
    fn basic_pairing(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let res = bls_pairing::compute_pairing(&a,&b);
        let prep = G2Prepared::from(b.get_element());

        assert_eq!(
            res,
            multi_miller_loop(&[(&a.get_element(), &prep)]).final_exponentiation()
        );

    }

    #[test]
    fn powers_of_g1_and_g2(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let scalar_factor:FE1 = ECScalar::new_random();
        let res_mul_a:GE1 = a.scalar_mul(&scalar_factor.get_element());
        let res_mul_b:GE2 = b.scalar_mul(&scalar_factor.get_element());
        let res_a_power = bls_pairing::compute_pairing(&res_mul_a,&b);
        let res_b_power = bls_pairing::compute_pairing(&a,&res_mul_b);
        assert_eq!(res_a_power,res_b_power);
    }

    #[test]
    fn powers_of_g1_and_gt_eq(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let scalar_factor:FE1 = ECScalar::new_random();
        let res_mul_a:GE1 = a.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = bls_pairing::compute_pairing(&res_mul_a,&b);
        let gt_direct_power = bls_pairing::compute_pairing(&a,&b)* scalar_factor.get_element();
        assert_eq!(gt_direct_power,gt_from_a_power);
    }

    #[test]
    #[should_panic]
    fn powers_of_g1_and_gt_not_eq(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let scalar_factor:FE1 = ECScalar::new_random();
        let scalar_factor_2:FE1 = ECScalar::new_random();
        let res_mul_a:GE1 = a.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = bls_pairing::compute_pairing(&res_mul_a,&b);
        let gt_direct_power = bls_pairing::compute_pairing(&a,&b)* scalar_factor.get_element();
        let gt_direct_power = bls_pairing::compute_pairing(&a,&b)* scalar_factor_2.get_element();
        assert_eq!(gt_direct_power,gt_from_a_power);
    }


    #[test]
    fn powers_of_g2_and_gt_eq(){
        let a:GE1 = ECPoint::generator();
        let b:GE2 = ECPoint::generator();
        let scalar_factor:FE1 = ECScalar::new_random();
        let res_mul_b:GE2 = b.scalar_mul(&scalar_factor.get_element());
        let gt_from_a_power = bls_pairing::compute_pairing(&a,&res_mul_b);
        let gt_direct_power = bls_pairing::compute_pairing(&a,&b)* scalar_factor.get_element();
        assert_eq!(gt_direct_power,gt_from_a_power);
    }


}