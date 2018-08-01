mod serde_secret_key {
    use elliptic::curves::traits::*;
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;
    use BigInt;
    use SK;

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_secret_key")]
    pub fn serialize<S: Serializer>(sk: &SK, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&sk.to_big_int().to_str_radix(10))
    }

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_secret_key")]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SK, D::Error> {
        struct SecretKeyVisitor;

        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = SK;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SecretKey")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<SK, E> {
                let v: SK = SK::from_big_int(&BigInt::from_str_radix(s, 10).unwrap());
                Ok(v)
            }
        }

        deserializer.deserialize_str(SecretKeyVisitor)
    }
}

mod serde_public_key {
    use elliptic::curves::traits::*;
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;
    use BigInt;
    use serde_json;
    use PK;
    use Point;

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_secret_key")]
    pub fn serialize<S: Serializer>(pk: &PK, serializer: S) -> Result<S::Ok, S::Error> {
        let s_point = serde_json::to_string(pk.to_point())
            .expect("Failed in serialization");

        serializer.serialize_str(&s_point)
    }

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_secret_key")]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PK, D::Error> {
        struct SecretKeyVisitor;

        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = PK;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("PublicKey")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<PK, E> {
                let point : Point = serde_json::from_str(s);
                let v: PK = PK::to_key(&point);
                Ok(v)
            }
        }

        deserializer.deserialize_str(SecretKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::serde_secret_key;
    use elliptic::curves::traits::*;
    use serde_json;
    use BigInt;
    use SK;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct DummyStruct {
        #[serde(with = "serde_secret_key")]
        sk: SK,
    }

    #[test]
    fn serialize() {
        let sk = SK::from_big_int(&BigInt::from(123456));
        let dummy = DummyStruct { sk };
        let s = serde_json::to_string(&dummy).expect("Failed in serialization");
        assert_eq!(s, "{\"sk\":\"123456\"}");
    }

    #[test]
    fn deserialize() {
        let s = "{\"sk\":\"123456\"}";
        let dummy: DummyStruct = serde_json::from_str(s).expect("Failed in serialization");

        let sk = SK::from_big_int(&BigInt::from(123456));
        let expected_dummy = DummyStruct { sk };

        assert_eq!(dummy, expected_dummy);
    }
}
