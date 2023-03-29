use std::fmt;

use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::traits::Converter;
use super::BigInt;

impl Serialize for BigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        if !serializer.is_human_readable() {
            serializer.serialize_bytes(&bytes)
        } else {
            serializer.serialize_str(&hex::encode(bytes))
        }
    }
}

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BigintVisitor;

        impl<'de> Visitor<'de> for BigintVisitor {
            type Value = BigInt;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "bigint")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BigInt::from_bytes(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = vec![];
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte)
                }
                Ok(BigInt::from_bytes(&bytes))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = hex::decode(v).map_err(|_| E::custom("malformed hex encoding"))?;
                Ok(BigInt::from_bytes(&bytes))
            }
        }

        if !deserializer.is_human_readable() {
            deserializer.deserialize_bytes(BigintVisitor)
        } else {
            deserializer.deserialize_str(BigintVisitor)
        }
    }
}
