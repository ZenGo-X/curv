/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use std::marker::PhantomData;

use digest::Digest;

use crate::arithmetic::traits::*;
use crate::BigInt;

use super::traits::Commitment;
use super::SECURITY_BITS;

//TODO: (open issue) use this struct to represent the commitment HashCommitment{comm: BigInt, r: BigInt, m: BigInt}
/// calculate commitment c = H(m,r) using SHA3 CRHF.
/// r is 256bit blinding factor, m is the commited value
pub struct HashCommitment<H: Digest + Clone>(PhantomData<H>);

//TODO:  using the function with BigInt's as input instead of string's makes it impossible to commit to empty message or use empty randomness
impl<H: Digest + Clone> Commitment<BigInt> for HashCommitment<H> {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> BigInt {
        let digest_result = H::new()
            .chain(message.to_bytes())
            .chain(blinding_factor.to_bytes())
            .finalize();
        BigInt::from_bytes(digest_result.as_ref())
    }

    fn create_commitment(message: &BigInt) -> (BigInt, BigInt) {
        let blinding_factor = BigInt::sample(SECURITY_BITS);
        let com = Self::create_commitment_with_user_defined_randomness(message, &blinding_factor);
        (com, blinding_factor)
    }
}

#[cfg(test)]
mod tests {
    use super::Commitment;
    use super::HashCommitment;
    use super::SECURITY_BITS;
    use crate::arithmetic::traits::*;
    use crate::{test_for_all_hashes, BigInt};
    use digest::Digest;

    test_for_all_hashes!(test_bit_length_create_commitment);
    fn test_bit_length_create_commitment<H: Digest + Clone>() {
        let hex_len = H::output_size() * 8;
        let mut ctr_commit_len = 0;
        let mut ctr_blind_len = 0;
        let sample_size = 10_000;
        for _ in 1..sample_size {
            let message = BigInt::sample(hex_len);
            let (commitment, blind_factor) = HashCommitment::<H>::create_commitment(&message);
            if commitment.bit_length() == hex_len {
                ctr_commit_len += 1;
            }
            // the blinding factor bit length is not related to the hash function.
            if blind_factor.bit_length() == SECURITY_BITS {
                ctr_blind_len += 1;
            }
        }
        //test commitment length  - works because SHA256 output length the same as sec_bits
        // we test that the probability distribution is according to what is expected. ideally = 0.5
        let ctr_commit_len = ctr_commit_len as f32;
        let ctr_blind_len = ctr_blind_len as f32;
        let sample_size = sample_size as f32;
        assert!(ctr_commit_len / sample_size > 0.3);
        assert!(ctr_blind_len / sample_size > 0.3);
    }

    test_for_all_hashes!(test_bit_length_create_commitment_with_user_defined_randomness);
    fn test_bit_length_create_commitment_with_user_defined_randomness<H: Digest + Clone>() {
        let sec_bits = H::output_size() * 8;
        let message = BigInt::sample(sec_bits);
        let (_commitment, blind_factor) = HashCommitment::<H>::create_commitment(&message);
        let commitment2 = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &message,
            &blind_factor,
        );
        assert!(commitment2.to_hex().len() / 2 <= sec_bits / 8);
    }

    test_for_all_hashes!(test_random_num_generation_create_commitment_with_user_defined_randomness);
    fn test_random_num_generation_create_commitment_with_user_defined_randomness<
        H: Digest + Clone,
    >() {
        let message = BigInt::sample(SECURITY_BITS);
        let (commitment, blind_factor) = HashCommitment::<H>::create_commitment(&message);
        let commitment2 = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &message,
            &blind_factor,
        );
        assert_eq!(commitment, commitment2);
    }

    test_for_all_hashes!(test_hashing_create_commitment_with_user_defined_randomness);
    fn test_hashing_create_commitment_with_user_defined_randomness<H: Digest + Clone>() {
        let mut digest = H::new();
        let message = BigInt::one();
        let commitment = HashCommitment::<H>::create_commitment_with_user_defined_randomness(
            &message,
            &BigInt::zero(),
        );
        let message2 = message.to_bytes();
        digest.update(&message2);
        let bytes_blinding_factor = &BigInt::zero().to_bytes();
        digest.update(&bytes_blinding_factor);
        let hash_result = BigInt::from_bytes(digest.finalize().as_ref());
        assert_eq!(&commitment, &hash_result);
    }
}
