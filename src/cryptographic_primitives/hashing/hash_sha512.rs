use BigInt;

use super::ring::digest::{Context, SHA512};
use super::traits::Hash;
use std::borrow::Borrow;

pub struct HSha512;

impl Hash for HSha512 {
    fn create_hash(big_ints: Vec<&BigInt>) -> BigInt {
        let mut digest = Context::new(&SHA512);

        for value in big_ints {
            let bytes: Vec<u8> = value.borrow().into();
            digest.update(&bytes);
        }

        BigInt::from(digest.finish().as_ref())
    }
}
