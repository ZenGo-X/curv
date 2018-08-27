mod serializing_bigint {

    use std::fmt;

    use serde::de::*;
    use serde::*;

    use arithmetic::big_gmp::BigInt;

    pub fn serialize<S: Serializer>(x: &BigInt, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&x.to_str_radix(10))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BigInt, D::Error> {
        struct BigIntVisitor;

        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = BigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bigint")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<BigInt, E> {
                let v: BigInt = BigInt::  str::parse(s).map_err(Error::custom)?;
                Ok(v)
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
        #[serde(with = "serializing_bigint")]
        a: BigInt,

        #[serde(with = "serializing_bigint")]
        b: BigInt,
    }

    #[test]
    fn test_serialize_deserialize() {
        let a: BigInt = str::parse("123456789").unwrap();
        let b: BigInt = str::parse("987654321").unwrap();
        let c = DummyContainer { a, b };

        let serialized = serde_json::to_string(&c).unwrap();
        assert_eq!(serialized, "{\"a\":\"123456789\",\"b\":\"987654321\"}");

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
        let illformatted = "{\"a\":\"123456789\"}";

        let result: Result<DummyContainer, _> = serde_json::from_str(&illformatted);
        assert!(result.is_err())
    }

    #[test]
    fn test_failing_non_numeric() {
        let illformatted = "{\"a\":\"i23456789\",\"b\":\"987654321\"}";

        let result: Result<DummyContainer, _> = serde_json::from_str(&illformatted);
        assert!(result.is_err())
    }

}