pub mod serde_secret_key {
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

pub mod serde_public_key {
    use elliptic::curves::traits::*;
    use serde::de::{Error, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{Deserializer, Serializer};
    use serde_json;
    use std::fmt;
    use Point;
    use PK;

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_public_key")]
    pub fn serialize<S: Serializer>(pk: &PK, serializer: S) -> Result<S::Ok, S::Error> {
        let point = pk.to_point();

        let mut state = serializer.serialize_struct("Point", 2)?;
        state.serialize_field("x", &point.x.to_str_radix(10))?;
        state.serialize_field("y", &point.x.to_str_radix(10))?;
        state.end()
    }

    #[allow(dead_code)]
    // This is not dead code, it used as part of the annotation #[serde(with = "serde_public_key")]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PK, D::Error> {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PK;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("PublicKey")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<PK, E> {
                let point = serde_json::from_str::<Point>(s).expect("Failed point");
                let v: PK = PK::to_key(&point);
                Ok(v)
            }
        }

        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::serde_public_key;
    use super::serde_secret_key;
    use elliptic::curves::traits::*;
    use serde_json;
    use BigInt;
    use EC;
    use PK;
    use SK;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct DummyStructSK {
        #[serde(with = "serde_secret_key")]
        sk: SK,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct DummyStructPK {
        #[serde(with = "serde_public_key")]
        pk: PK,
    }

    #[test]
    fn serialize_sk() {
        let sk = SK::from_big_int(&BigInt::from(123456));
        let dummy = DummyStructSK { sk };
        let s = serde_json::to_string(&dummy).expect("Failed in serialization");
        assert_eq!(s, "{\"sk\":\"123456\"}");
    }

    #[test]
    fn deserialize_sk() {
        let s = "{\"sk\":\"123456\"}";
        let dummy: DummyStructSK = serde_json::from_str(s).expect("Failed in serialization");

        let sk = SK::from_big_int(&BigInt::from(123456));
        let expected_dummy = DummyStructSK { sk };

        assert_eq!(dummy, expected_dummy);
    }

    #[test]
    fn serialize_pk() {
        let slice = &[
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let uncompressed_key = PK::from_slice(&EC::without_caps(), slice).unwrap();
        let p = uncompressed_key.to_point();

        let pk = PK::to_key(&p);
        let dummy = DummyStructPK { pk };
        let s = serde_json::to_string(&dummy).expect("Failed in serialization");
        assert_eq!(s, "{\"pk\":{\
            \"x\":\"24526638926943435805455894225888021349399091104478482819438411584402369425843\",\
            \"y\":\"24526638926943435805455894225888021349399091104478482819438411584402369425843\"}}");
    }

    #[test]
    fn deserialize_pk() {
        let s = "{\"pk\":{\
            \"x\":\"24526638926943435805455894225888021349399091104478482819438411584402369425843\",\
            \"y\":\"24526638926943435805455894225888021349399091104478482819438411584402369425843\"}}";

        let dummy: DummyStructPK = serde_json::from_str(s).expect("Failed in serialization");

        let slice = &[
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];
        let uncompressed_key = PK::from_slice(&EC::without_caps(), slice).unwrap();
        let p = uncompressed_key.to_point();

        let pk_expected = PK::to_key(&p);
        assert_eq!(dummy.pk, pk_expected);
    }
}
