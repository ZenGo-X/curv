/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use arithmetic::traits::Converter;
use blake2_rfc::blake2b::Blake2b;
use elliptic::curves::traits::{ECPoint, ECScalar};
use BigInt;
use {FE, GE};

pub struct Blake;

impl Blake {
    pub fn create_hash(big_ints: &[&BigInt], persona: &[u8]) -> BigInt {
        let mut digest = Blake2b::with_params(64, &[], &[], persona);
        for value in big_ints {
            digest.update(&BigInt::to_vec(value));
        }

        BigInt::from(digest.finalize().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::Blake;
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use BigInt;
    use GE;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        let result =
            Blake::create_hash(&vec![&BigInt::one(), &BigInt::zero()], b"Zcash_RedJubjubH");
        assert!(result > BigInt::zero());
    }

}
