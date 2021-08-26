/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use blake2b_simd::{Params, State};
use typenum::Unsigned;

use crate::arithmetic::traits::*;
use crate::elliptic::curves::{Curve, ECScalar, Point, Scalar};
use crate::BigInt;

/// Wrapper over [blake2b_simd](blake2b_simd::State) exposing facilities to hash bigints, elliptic points,
/// and scalars
pub struct Blake {
    state: State,
}

impl Blake {
    const HASH_LENGTH: usize = 64;
    pub fn with_personal(persona: &[u8]) -> Self {
        Self {
            state: Params::new()
                .hash_length(Self::HASH_LENGTH)
                .personal(persona)
                .to_state(),
        }
    }

    pub fn chain_bigint(&mut self, n: &BigInt) -> &mut Self {
        self.state.update(&n.to_bytes());
        self
    }

    pub fn chain_point<E: Curve>(&mut self, point: &Point<E>) -> &mut Self {
        self.state.update(&point.to_bytes(false));
        self
    }

    pub fn result_bigint(&self) -> BigInt {
        BigInt::from_bytes(self.state.finalize().as_ref())
    }

    pub fn result_scalar<E: Curve>(&self) -> Scalar<E> {
        let scalar_len = <<E::Scalar as ECScalar>::ScalarLength as Unsigned>::to_usize();
        assert!(
            Self::HASH_LENGTH >= scalar_len,
            "Output size of the hash({}) is smaller than the scalar length({})",
            Self::HASH_LENGTH,
            scalar_len
        );
        // Try and increment.
        for i in 0u32.. {
            let mut starting_state = self.state.clone();
            let hash = starting_state.update(&i.to_be_bytes()).finalize();
            if let Ok(scalar) = Scalar::from_bytes(&hash.as_bytes()[..scalar_len]) {
                return scalar;
            }
        }
        unreachable!("The probably of this reaching is extremely small ((2^n-q)/(2^n))^(2^32)")
    }

    #[deprecated(
        since = "0.8.0",
        note = "Blake API has been changed, this method is outdated"
    )]
    pub fn create_hash(big_ints: &[&BigInt], persona: &[u8]) -> BigInt {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        for value in big_ints {
            digest.update(&BigInt::to_bytes(value));
        }

        BigInt::from_bytes(digest.finalize().as_ref())
    }

    #[deprecated(
        since = "0.8.0",
        note = "Blake API has been changed, this method is outdated"
    )]
    pub fn create_hash_from_ge<E: Curve>(ge_vec: &[&Point<E>], persona: &[u8]) -> Scalar<E> {
        let mut digest = Params::new().hash_length(64).personal(persona).to_state();
        //  let mut digest = Blake2b::with_params(64, &[], &[], persona);

        for value in ge_vec {
            digest.update(&value.to_bytes(false));
        }

        let result = BigInt::from_bytes(digest.finalize().as_ref());
        Scalar::from(&result)
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
    fn create_hash_test_legacy() {
        #![allow(deprecated)]
        let result = Blake::create_hash(&[&BigInt::one(), &BigInt::zero()], b"Zcash_RedJubjubH");
        assert!(result > BigInt::zero());
    }
    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        let result = Blake::with_personal(b"Zcash_RedJubjubH")
            .chain_bigint(&BigInt::one())
            .chain_bigint(&BigInt::zero())
            .result_bigint();
        assert!(result > BigInt::zero());
    }

    crate::test_for_all_curves!(create_hash_from_ge_test_legacy);
    fn create_hash_from_ge_test_legacy<E: Curve>() {
        #![allow(deprecated)]
        let base_point2 = Point::<E>::base_point2();
        let generator = Point::<E>::generator();
        let result1 =
            Blake::create_hash_from_ge::<E>(&[base_point2, &generator], b"Zcash_RedJubjubH");
        assert!(result1.to_bigint().bit_length() > 240);
        let result2 = Blake::create_hash_from_ge(&[&generator, base_point2], b"Zcash_RedJubjubH");
        assert_ne!(result1, result2);
        let result3 = Blake::create_hash_from_ge(&[&generator, base_point2], b"Zcash_RedJubjubH");
        assert_eq!(result2, result3);
    }

    crate::test_for_all_curves!(create_hash_from_ge_test);
    fn create_hash_from_ge_test<E: Curve>() {
        let base_point2 = Point::<E>::base_point2();
        let generator = Point::<E>::generator();
        let result1 = Blake::with_personal(b"Zcash_RedJubjubH")
            .chain_point(base_point2)
            .chain_point(&generator)
            .result_scalar::<E>();
        assert!(result1.to_bigint().bit_length() > 240);
        let result2 = Blake::with_personal(b"Zcash_RedJubjubH")
            .chain_point(&generator)
            .chain_point(base_point2)
            .result_scalar::<E>();
        assert_ne!(result1, result2);
        let result3 = Blake::with_personal(b"Zcash_RedJubjubH")
            .chain_point(&generator)
            .chain_point(base_point2)
            .result_scalar::<E>();
        assert_eq!(result2, result3);
    }
}
