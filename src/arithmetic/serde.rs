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

pub mod serde_bigint {

    use std::fmt;

    use serde::de::*;
    use serde::*;

    use arithmetic::big_gmp::BigInt;
    use arithmetic::traits::Converter;

    pub fn serialize<S: Serializer>(x: &BigInt, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&x.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BigInt, D::Error> {
        struct BigIntVisitor;

        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = BigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bigint")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<BigInt, E> {
                Ok(BigInt::from_hex(&String::from(s)))
            }
        }

        deserializer.deserialize_str(BigIntVisitor)
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use arithmetic::big_gmp::BigInt;

    extern crate serde_json;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct DummyContainer {
        #[serde(with = "serde_bigint")]
        a: BigInt,

        #[serde(with = "serde_bigint")]
        b: BigInt,
    }

    #[test]
    fn test_serialize_deserialize() {
        let a: BigInt = str::parse("123456789").unwrap();
        let b: BigInt = str::parse("987654321").unwrap();
        let c = DummyContainer { a, b };

        let serialized = serde_json::to_string(&c).unwrap();
        assert_eq!(serialized, "{\"a\":\"75bcd15\",\"b\":\"3ade68b1\"}");

        let d: DummyContainer = serde_json::from_str(&serialized).unwrap();
        assert_eq!(d, c)
    }

    #[test]
    fn test_failing_empty() {
        let illformatted = "";

        let result: Result<DummyContainer, _> = serde_json::from_str(&illformatted);
        assert!(result.is_err())
    }

    #[test]
    fn test_failing_missing_field() {
        let illformatted = "{\"a\":\"75bcd15\"}";

        let result: Result<DummyContainer, _> = serde_json::from_str(&illformatted);
        assert!(result.is_err())
    }
}