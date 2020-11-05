/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/
use crate::arithmetic::traits::Converter;
use crate::elliptic::curves::traits::{ECPoint, ECScalar};
use crate::BigInt;
use blake2b_simd::Params;

pub struct Blake;

impl Blake {
    pub fn create_hash(big_ints: &[&BigInt], persona: &[u8]) -> BigInt {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        // let mut digest = Blake2b::with_params(64, &[], &[], persona);
        for value in big_ints {
            digest.update(&BigInt::to_vec(value));
        }

        BigInt::from(digest.finalize().as_ref())
    }

    pub fn create_hash_from_ge<P: ECPoint>(ge_vec: &[&P], persona: &[u8]) -> P::Scalar {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        //  let mut digest = Blake2b::with_params(64, &[], &[], persona);

        for value in ge_vec {
            digest.update(&value.pk_to_key_slice());
        }

        let result = BigInt::from(digest.finalize().as_ref());
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::Blake;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        let result =
            Blake::create_hash(&vec![&BigInt::one(), &BigInt::zero()], b"Zcash_RedJubjubH");
        assert!(result > BigInt::zero());
    }

    crate::test_for_all_curves!(create_hash_from_ge_test);

    fn create_hash_from_ge_test<P>()
    where
        P: ECPoint,
        P::Scalar: PartialEq + std::fmt::Debug,
    {
        let point = P::base_point2();
        let result1 =
            Blake::create_hash_from_ge(&vec![&point, &P::generator()], b"Zcash_RedJubjubH");
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 =
            Blake::create_hash_from_ge(&vec![&P::generator(), &point], b"Zcash_RedJubjubH");
        assert_ne!(result1, result2);
        let result3 =
            Blake::create_hash_from_ge(&vec![&P::generator(), &point], b"Zcash_RedJubjubH");
        assert_eq!(result2, result3);
    }
}
