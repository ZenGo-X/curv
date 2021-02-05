/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

mod big_gmp;
mod errors;
pub mod traits;

pub use big_gmp::BigInt;
pub use errors::{ParseBigIntFromHexError, TryFromBigIntError};
pub use traits::*;

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::*;

    /// This test will fail to compile if BigInt doesn't implement certain traits.
    #[test]
    fn big_int_implements_all_required_trait() {
        assert_big_int_implements_all_required_traits::<BigInt>();
    }

    /// A no-op function that takes BigInt implementation as a generic param. It's only purpose
    /// is to abort compilation if BigInt doesn't implement certain traits.
    #[allow(deprecated)]
    fn assert_big_int_implements_all_required_traits<T>()
    where
        // Basic traits from self::traits module
        T: Converter + BasicOps + Modulo + Samplable + NumberTests + EGCD + BitManipulation,
        // Deprecated but not deleted yet traits from self::traits module
        T: ZeroizeBN,
        u64: ConvertFrom<BigInt>,
        // Foreign traits implementations
        T: zeroize::Zeroize + ring_algorithm::RingNormalize + num_traits::One + num_traits::Zero,
        for<'a> &'a T: ring_algorithm::EuclideanRingOperation<T>,
        // Conversion traits
        for<'a> u64: std::convert::TryFrom<&'a BigInt>,
        for<'a> i64: std::convert::TryFrom<&'a BigInt>,
        for<'a> BigInt: From<&'a [u8]> + From<u32> + From<i32> + From<u64>,
        // Operators
        BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        for<'a> &'a BigInt: Add<Output = BigInt>
            + Sub<Output = BigInt>
            + Mul<Output = BigInt>
            + Div<Output = BigInt>
            + Rem<Output = BigInt>
            + BitXor<Output = BigInt>,
        for<'a> &'a BigInt: Add<&'a BigInt, Output = BigInt>
            + Sub<&'a BigInt, Output = BigInt>
            + Mul<&'a BigInt, Output = BigInt>
            + Div<&'a BigInt, Output = BigInt>
            + Rem<&'a BigInt, Output = BigInt>
            + BitXor<&'a BigInt, Output = BigInt>,
        BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
        for<'a> &'a BigInt: Shl<usize, Output = BigInt> + Shr<usize, Output = BigInt>,
    {
    }
}
