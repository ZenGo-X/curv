mod serializing_bigint {

    use std::fmt;
    
    use serde::*;
    use serde::de::*;

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
                let v: BigInt = str::parse(s).map_err(Error::custom)?;
                Ok(v)
            }
        }

        deserializer.deserialize_str(BigIntVisitor)
    }

}
