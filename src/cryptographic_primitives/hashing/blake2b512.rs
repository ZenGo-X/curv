/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/
use crate::arithmetic::traits::*;
use crate::elliptic::curves::{Curve, Point, PointZ, ScalarZ};
use crate::BigInt;
use blake2b_simd::Params;

pub struct Blake;

impl Blake {
    pub fn create_hash(big_ints: &[&BigInt], persona: &[u8]) -> BigInt {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        for value in big_ints {
            digest.update(&BigInt::to_bytes(value));
        }

        BigInt::from_bytes(digest.finalize().as_ref())
    }

    pub fn create_hash_from_ge<E: Curve>(ge_vec: &[&Point<E>], persona: &[u8]) -> ScalarZ<E> {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        //  let mut digest = Blake2b::with_params(64, &[], &[], persona);

        for value in ge_vec {
            digest.update(&value.to_bytes(false));
        }

        let result = BigInt::from_bytes(digest.finalize().as_ref());
        ScalarZ::from(&result)
    }

    pub fn create_hash_from_ge_z<E: Curve>(ge_vec: &[&PointZ<E>], persona: &[u8]) -> ScalarZ<E> {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        //  let mut digest = Blake2b::with_params(64, &[], &[], persona);

        for value in ge_vec {
            match value.to_bytes(false) {
                Some(serialized) => digest.update(&serialized),
                None => digest.update(b"infinity point"),
            };
        }

        let result = BigInt::from_bytes(digest.finalize().as_ref());
        ScalarZ::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::Blake;
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::{Curve, Point};
    use crate::BigInt;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        let result = Blake::create_hash(&[&BigInt::one(), &BigInt::zero()], b"Zcash_RedJubjubH");
        assert!(result > BigInt::zero());
    }

    crate::test_for_all_curves!(create_hash_from_ge_test);

    fn create_hash_from_ge_test<E: Curve>() {
        let base_point2 = Point::base_point2().to_point();
        let generator = Point::generator().to_point();
        let result1 =
            Blake::create_hash_from_ge::<E>(&[&base_point2, &generator], b"Zcash_RedJubjubH");
        assert!(result1.to_bigint().bit_length() > 240);
        let result2 = Blake::create_hash_from_ge(&[&generator, &base_point2], b"Zcash_RedJubjubH");
        assert_ne!(result1, result2);
        let result3 = Blake::create_hash_from_ge(&[&generator, &base_point2], b"Zcash_RedJubjubH");
        assert_eq!(result2, result3);
    }
}
