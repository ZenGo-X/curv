use digest::Digest;
use generic_array::GenericArray;
use hmac::crypto_mac::MacError;
use hmac::{Hmac, Mac, NewMac};
use typenum::Unsigned;

use crate::arithmetic::*;
use crate::elliptic::curves::{Curve, ECScalar, Point, Scalar};

/// [Digest] extension allowing to hash elliptic points, scalars, and bigints
///
/// Can be used with any hashing algorithm that implements `Digest` traits (e.g. [Sha256](sha2::Sha256),
/// [Sha512](sha2::Sha512), etc.)
///
/// ## Example
///
/// ```rust
/// use sha2::Sha256;
/// use curv::arithmetic::*;
/// use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
/// use curv::elliptic::curves::{Secp256k1, Point};
///
/// let hash = Sha256::new()
///     .chain_point(&Point::<Secp256k1>::generator())
///     .chain_point(Point::<Secp256k1>::base_point2())
///     .chain_bigint(&BigInt::from(10))
///     .result_bigint();
///
/// assert_eq!(hash, BigInt::from_hex("73764f937fbe25092466b417fa66ad9c62607865e1f8151df253aa3a2fd7599b").unwrap());
/// ```
pub trait DigestExt {
    fn input_bigint(&mut self, n: &BigInt);
    fn input_point<E: Curve>(&mut self, point: &Point<E>);
    fn input_scalar<E: Curve>(&mut self, scalar: &Scalar<E>);

    fn chain_bigint(mut self, n: &BigInt) -> Self
    where
        Self: Sized,
    {
        self.input_bigint(n);
        self
    }
    fn chain_point<E: Curve>(mut self, point: &Point<E>) -> Self
    where
        Self: Sized,
    {
        self.input_point(point);
        self
    }
    fn chain_points<'p, E: Curve>(mut self, points: impl IntoIterator<Item = &'p Point<E>>) -> Self
    where
        Self: Sized,
    {
        for point in points {
            self.input_point(point)
        }
        self
    }
    fn chain_scalar<E: Curve>(mut self, scalar: &Scalar<E>) -> Self
    where
        Self: Sized,
    {
        self.input_scalar(scalar);
        self
    }
    fn chain_scalars<'s, E: Curve>(
        mut self,
        scalars: impl IntoIterator<Item = &'s Scalar<E>>,
    ) -> Self
    where
        Self: Sized,
    {
        for scalar in scalars {
            self.input_scalar(scalar)
        }
        self
    }

    fn result_bigint(self) -> BigInt;
    fn result_scalar<E: Curve>(self) -> Scalar<E>;

    fn digest_bigint(bytes: &[u8]) -> BigInt;
}

impl<D> DigestExt for D
where
    D: Digest + Clone,
{
    fn input_bigint(&mut self, n: &BigInt) {
        self.update(&n.to_bytes())
    }

    fn input_point<E: Curve>(&mut self, point: &Point<E>) {
        self.update(&point.to_bytes(false)[..])
    }

    fn input_scalar<E: Curve>(&mut self, scalar: &Scalar<E>) {
        self.update(&scalar.to_bigint().to_bytes())
    }

    fn result_bigint(self) -> BigInt {
        let result = self.finalize();
        BigInt::from_bytes(&result)
    }

    fn result_scalar<E: Curve>(self) -> Scalar<E> {
        let scalar_len = <<E::Scalar as ECScalar>::ScalarLength as Unsigned>::to_usize();
        assert!(
            Self::output_size() >= scalar_len,
            "Output size of the hash({}) is smaller than the scalar length({})",
            Self::output_size(),
            scalar_len
        );
        // Try and increment.
        for i in 0u32.. {
            let starting_state = self.clone();
            let hash = starting_state.chain(i.to_be_bytes()).finalize();
            if let Ok(scalar) = Scalar::from_bytes(&hash[..scalar_len]) {
                return scalar;
            }
        }
        unreachable!("The probably of this reaching is extremely small ((2^n-q)/(2^n))^(2^32)")
    }

    fn digest_bigint(bytes: &[u8]) -> BigInt {
        Self::new().chain(bytes).result_bigint()
    }
}

/// [Hmac] extension allowing to use bigints to instantiate hmac, update, and finalize it.
pub trait HmacExt: Sized {
    fn new_bigint(key: &BigInt) -> Self;

    fn input_bigint(&mut self, n: &BigInt);

    fn chain_bigint(mut self, n: &BigInt) -> Self
    where
        Self: Sized,
    {
        self.input_bigint(n);
        self
    }

    fn result_bigint(self) -> BigInt;
    fn verify_bigint(self, code: &BigInt) -> Result<(), MacError>;
}

impl<D> HmacExt for Hmac<D>
where
    D: digest::Update + digest::BlockInput + digest::FixedOutput + digest::Reset + Default + Clone,
{
    fn new_bigint(key: &BigInt) -> Self {
        let bytes = key.to_bytes();
        Self::new_from_slice(&bytes).expect("HMAC must take a key of any length")
    }

    fn input_bigint(&mut self, n: &BigInt) {
        self.update(&n.to_bytes())
    }

    fn result_bigint(self) -> BigInt {
        BigInt::from_bytes(&self.finalize().into_bytes())
    }

    fn verify_bigint(self, code: &BigInt) -> Result<(), MacError> {
        let mut code_array = GenericArray::<u8, <D as digest::FixedOutput>::OutputSize>::default();
        let code_length = code_array.len();
        let bytes = code.to_bytes();
        if bytes.len() > code_length {
            return Err(MacError);
        }
        code_array[code_length - bytes.len()..].copy_from_slice(&bytes);
        self.verify(&code_array)
    }
}

#[cfg(test)]
mod test {
    use digest::generic_array::ArrayLength;
    use digest::{BlockInput, FixedOutput, Reset, Update};
    use hmac::Hmac;
    use sha2::{Sha256, Sha512};

    use super::*;

    // Test Vectors taken from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
    #[test]
    fn vector_sha256_test() {
        // Empty Message
        let result: BigInt = Sha256::new().result_bigint();
        assert_eq!(
            result.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // 256 bit message
        let result: BigInt = Sha256::new()
            .chain_bigint(
                &BigInt::from_hex(
                    "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95",
                )
                .unwrap(),
            )
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 2x128 bit messages
        let result: BigInt = Sha256::new()
            .chain_bigint(&BigInt::from_hex("09fc1accc230a205e4a208e64a8f2042").unwrap())
            .chain_bigint(&BigInt::from_hex("91f581a12756392da4b8c0cf5ef02b95").unwrap())
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
        );

        // 512 bit message
        let result: BigInt = Sha256::new()
            .chain_bigint(&BigInt::from_hex("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509").unwrap())
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa"
        );
    }

    #[test]
    // Test Vectors taken from:
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
    fn vector_sha512_test() {
        // Empty message
        let result: BigInt = Sha512::new().result_bigint();
        assert_eq!(
            result.to_hex(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );

        // 2x256 bit message
        let result: BigInt = Sha512::new()
            .chain_bigint(
                &BigInt::from_hex(
                    "c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f7",
                )
                .unwrap(),
            )
            .chain_bigint(
                &BigInt::from_hex(
                    "9d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d",
                )
                .unwrap(),
            )
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "46e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d"
        );

        // 512 bit message
        let result: BigInt = Sha512::new()
            .chain_bigint(&BigInt::from_hex(
                "c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f79d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d").unwrap())
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "46e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d"
        );

        // 1024 bit message
        let result: BigInt = Sha512::new()
            .chain_bigint(&BigInt::from_hex("fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8").unwrap())
            .result_bigint();
        assert_eq!(
            result.to_hex(),
            "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc"
        );
    }

    crate::test_for_all_curves_and_hashes!(create_hash_from_ge_test);
    fn create_hash_from_ge_test<E: Curve, H: Digest + Clone>() {
        let generator = Point::<E>::generator();
        let base_point2 = Point::<E>::base_point2();
        let result1 = H::new()
            .chain_point(&generator)
            .chain_point(base_point2)
            .result_scalar::<E>();
        assert!(result1.to_bigint().bit_length() > 240);
        let result2 = H::new()
            .chain_point(base_point2)
            .chain_point(&generator)
            .result_scalar::<E>();
        assert_ne!(result1, result2);
        let result3 = H::new()
            .chain_point(base_point2)
            .chain_point(&generator)
            .result_scalar::<E>();
        assert_eq!(result2, result3);
    }

    crate::test_for_all_hashes!(create_hmac_test);
    fn create_hmac_test<H>()
    where
        H: Update + BlockInput + FixedOutput + Reset + Default + Clone,
        H::BlockSize: ArrayLength<u8>,
        H::OutputSize: ArrayLength<u8>,
    {
        let key = BigInt::sample(512);
        let result1 = Hmac::<H>::new_bigint(&key)
            .chain_bigint(&BigInt::from(10))
            .result_bigint();
        assert!(Hmac::<H>::new_bigint(&key)
            .chain_bigint(&BigInt::from(10))
            .verify_bigint(&result1)
            .is_ok());

        let key2 = BigInt::sample(512);
        // same data , different key
        let result2 = Hmac::<H>::new_bigint(&key2)
            .chain_bigint(&BigInt::from(10))
            .result_bigint();
        assert_ne!(result1, result2);
        // same key , different data
        let result3 = Hmac::<H>::new_bigint(&key)
            .chain_bigint(&BigInt::from(10))
            .chain_bigint(&BigInt::from(11))
            .result_bigint();
        assert_ne!(result1, result3);
        // same key, same data
        let result4 = Hmac::<H>::new_bigint(&key)
            .chain_bigint(&BigInt::from(10))
            .result_bigint();
        assert_eq!(result1, result4)
    }
}
