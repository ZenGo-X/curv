use std::fmt;
use std::marker::PhantomData;

use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::elliptic::curves::{Curve, Point, Scalar};

// ---
// --- Point (de)serialization
// ---

impl<E: Curve> Serialize for Point<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_point().serialize(serializer)
    }
}

impl<'de, E: Curve> Deserialize<'de> for Point<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PointVisitor<E: Curve>(PhantomData<E>);

        impl<'de, E: Curve> Visitor<'de> for PointVisitor<E> {
            type Value = Point<E>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "point of {} curve", E::CURVE_NAME)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut curve_name: Option<CurveNameGuard<E>> = None;
                let mut point: Option<PointFromBytes<E>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        PointField::Curve => {
                            if curve_name.is_some() {
                                return Err(A::Error::duplicate_field("curve_name"));
                            }
                            curve_name = Some(map.next_value()?)
                        }
                        PointField::Point => {
                            if point.is_some() {
                                return Err(A::Error::duplicate_field("point"));
                            }
                            point = Some(map.next_value()?)
                        }
                    }
                }
                let _curve_name =
                    curve_name.ok_or_else(|| A::Error::missing_field("curve_name"))?;
                let point = point.ok_or_else(|| A::Error::missing_field("point"))?;
                Ok(point.0)
            }
        }

        deserializer.deserialize_struct("Point", &["curve", "point"], PointVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum PointField {
    Curve,
    Point,
}

/// Efficient guard for asserting that deserialized `&str`/`String` is `E::CURVE_NAME`
struct CurveNameGuard<E: Curve>(PhantomData<E>);

impl<'de, E: Curve> Deserialize<'de> for CurveNameGuard<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CurveNameVisitor<E: Curve>(PhantomData<E>);

        impl<'de, E: Curve> Visitor<'de> for CurveNameVisitor<E> {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "curve name (constrained to be '{}')", E::CURVE_NAME)
            }

            fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
            where
                Err: Error,
            {
                if v == E::CURVE_NAME {
                    Ok(())
                } else {
                    Err(Err::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &E::CURVE_NAME,
                    ))
                }
            }
        }

        deserializer
            .deserialize_str(CurveNameVisitor(PhantomData::<E>))
            .map(|_| CurveNameGuard(PhantomData))
    }
}

struct PointFromBytes<E: Curve>(Point<E>);

impl<'de, E: Curve> Deserialize<'de> for PointFromBytes<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PointBytesVisitor<E: Curve>(PhantomData<E>);

        impl<'de, E: Curve> Visitor<'de> for PointBytesVisitor<E> {
            type Value = Point<E>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "point of {} curve", E::CURVE_NAME)
            }

            fn visit_bytes<Err>(self, v: &[u8]) -> Result<Self::Value, Err>
            where
                Err: Error,
            {
                Point::from_bytes(v).map_err(|e| Err::custom(format!("invalid point: {}", e)))
            }
        }

        deserializer
            .deserialize_bytes(PointBytesVisitor(PhantomData))
            .map(PointFromBytes)
    }
}

// ---
// --- Scalar (de)serialization
// ---

impl<E: Curve> Serialize for Scalar<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Scalar", 2)?;
        s.serialize_field("curve", E::CURVE_NAME)?;
        s.serialize_field(
            "scalar",
            // Serializes bytes efficiently
            serde_bytes::Bytes::new(&self.to_bytes()),
        )?;
        s.end()
    }
}

impl<'de, E: Curve> Deserialize<'de> for Scalar<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor<E: Curve>(PhantomData<E>);

        impl<'de, E: Curve> Visitor<'de> for ScalarVisitor<E> {
            type Value = Scalar<E>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "scalar of {} curve", E::CURVE_NAME)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut curve_name: Option<CurveNameGuard<E>> = None;
                let mut scalar: Option<ScalarFromBytes<E>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        ScalarField::Curve => {
                            if curve_name.is_some() {
                                return Err(A::Error::duplicate_field("curve_name"));
                            }
                            curve_name = Some(map.next_value()?)
                        }
                        ScalarField::Scalar => {
                            if scalar.is_some() {
                                return Err(A::Error::duplicate_field("scalar"));
                            }
                            scalar = Some(map.next_value()?)
                        }
                    }
                }
                let _curve_name =
                    curve_name.ok_or_else(|| A::Error::missing_field("curve_name"))?;
                let scalar = scalar.ok_or_else(|| A::Error::missing_field("scalar"))?;
                Ok(scalar.0)
            }
        }

        deserializer.deserialize_struct("Scalar", &["curve", "scalar"], ScalarVisitor(PhantomData))
    }
}

struct ScalarFromBytes<E: Curve>(Scalar<E>);

impl<'de, E: Curve> Deserialize<'de> for ScalarFromBytes<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarBytesVisitor<E: Curve>(PhantomData<E>);

        impl<'de, E: Curve> Visitor<'de> for ScalarBytesVisitor<E> {
            type Value = Scalar<E>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "scalar value of {} curve", E::CURVE_NAME)
            }

            fn visit_bytes<Err>(self, v: &[u8]) -> Result<Self::Value, Err>
            where
                Err: Error,
            {
                Scalar::from_bytes(v).map_err(|_| Err::custom("invalid scalar"))
            }
        }

        deserializer
            .deserialize_bytes(ScalarBytesVisitor(PhantomData))
            .map(ScalarFromBytes)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum ScalarField {
    Curve,
    Scalar,
}

#[cfg(test)]
mod serde_tests {
    use serde_test::{assert_tokens, Token::*};

    use crate::elliptic::curves::*;

    #[test]
    fn test_serde_point() {
        fn generic<E: Curve>(point: Point<E>) {
            let bytes = point.to_bytes(true).to_vec();
            let tokens = vec![
                Struct {
                    name: "Point",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("point"),
                Bytes(bytes.leak()),
                StructEnd,
            ];
            assert_tokens(&point, &tokens);
        }

        // Test **zero points** (de)serializing
        generic::<Secp256k1>(Point::zero());
        generic::<Secp256r1>(Point::zero());
        generic::<Ed25519>(Point::zero());
        generic::<Ristretto>(Point::zero());
        generic::<Bls12_381_1>(Point::zero());
        generic::<Bls12_381_2>(Point::zero());

        // Test **random point** (de)serializing
        generic::<Secp256k1>(Point::generator() * Scalar::random());
        generic::<Secp256r1>(Point::generator() * Scalar::random());
        generic::<Ed25519>(Point::generator() * Scalar::random());
        generic::<Ristretto>(Point::generator() * Scalar::random());
        generic::<Bls12_381_1>(Point::generator() * Scalar::random());
        generic::<Bls12_381_2>(Point::generator() * Scalar::random());
    }

    #[test]
    fn test_serde_scalar() {
        fn generic<E: Curve>(scalar: Scalar<E>) {
            let bytes = scalar.to_bytes().to_vec();
            let tokens = vec![
                Struct {
                    name: "Scalar",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("scalar"),
                Bytes(bytes.leak()),
                StructEnd,
            ];
            assert_tokens(&scalar, &tokens);
        }

        // Test **zero scalars** (de)serializing
        generic::<Secp256k1>(Scalar::zero());
        generic::<Secp256r1>(Scalar::zero());
        generic::<Ed25519>(Scalar::zero());
        generic::<Ristretto>(Scalar::zero());
        generic::<Bls12_381_1>(Scalar::zero());
        generic::<Bls12_381_2>(Scalar::zero());

        // Test **random scalars** (de)serializing
        generic::<Secp256k1>(Scalar::random());
        generic::<Secp256r1>(Scalar::random());
        generic::<Ed25519>(Scalar::random());
        generic::<Ristretto>(Scalar::random());
        generic::<Bls12_381_1>(Scalar::random());
        generic::<Bls12_381_2>(Scalar::random());
    }
}
