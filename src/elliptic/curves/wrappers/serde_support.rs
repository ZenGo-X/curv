use std::fmt;
use std::marker::PhantomData;

use serde::de::{Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::Bytes;

use generic_array::GenericArray;
use typenum::Unsigned;

use crate::elliptic::curves::{Curve, ECPoint, ECScalar, Point, Scalar};

// ---
// --- Point (de)serialization
// ---

impl<E: Curve> Serialize for Point<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut s = serializer.serialize_struct("Point", 2)?;
        s.serialize_field("curve", E::CURVE_NAME)?;
        if !is_human_readable {
            s.serialize_field(
                "point",
                // Serializes bytes efficiently
                Bytes::new(&self.to_bytes(true)),
            )?;
        } else {
            s.serialize_field("point", &hex::encode(&*self.to_bytes(true)))?;
        }
        s.end()
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

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if let Some(size) = seq.size_hint() {
                    if size != 2 {
                        return Err(A::Error::invalid_length(size, &"2"));
                    }
                }
                let _curve_name: CurveNameGuard<E> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::missing_field("curve name"))?;
                let point: PointFromBytes<E> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::missing_field("point value"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("point consist of too many fields"));
                }
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
                    Err(Err::custom(format!(
                        "belongs to {} curve, expected {} curve",
                        v,
                        E::CURVE_NAME
                    )))
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

            // serde_json serializes bytes as a sequence of u8, so we need to support this format too
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let seq_len_hint = seq.size_hint();
                let uncompressed_len = <E::Point as ECPoint>::UncompressedPointLength::USIZE;
                let compressed_len = <E::Point as ECPoint>::CompressedPointLength::USIZE;

                let mut buffer =
                    GenericArray::<u8, <E::Point as ECPoint>::UncompressedPointLength>::default();
                let mut seq_len = 0;

                for x in buffer.iter_mut() {
                    *x = match seq.next_element()? {
                        Some(b) => b,
                        None => break,
                    };
                    seq_len += 1;
                }

                if seq_len == uncompressed_len {
                    // Ensure that there are no other elements in the sequence
                    if seq.next_element::<IgnoredAny>()?.is_some() {
                        return Err(A::Error::invalid_length(
                            seq_len_hint.unwrap_or(seq_len + 1),
                            &format!("either {} or {} bytes", compressed_len, uncompressed_len)
                                .as_str(),
                        ));
                    }
                } else if seq_len != compressed_len {
                    return Err(A::Error::invalid_length(
                        seq_len_hint.unwrap_or(seq_len),
                        &format!("either {} or {} bytes", compressed_len, uncompressed_len)
                            .as_str(),
                    ));
                }

                Point::from_bytes(&buffer.as_slice()[..seq_len])
                    .map_err(|e| A::Error::custom(format!("invalid point: {}", e)))
            }

            fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
            where
                Err: Error,
            {
                let uncompressed_len = <E::Point as ECPoint>::UncompressedPointLength::USIZE;
                let compressed_len = <E::Point as ECPoint>::CompressedPointLength::USIZE;

                let mut buffer =
                    GenericArray::<u8, <E::Point as ECPoint>::UncompressedPointLength>::default();

                let point = if uncompressed_len * 2 == v.len() {
                    hex::decode_to_slice(v, &mut buffer)
                        .map_err(|_| Err::custom("malformed hex encoding"))?;
                    Point::from_bytes(&buffer)
                        .map_err(|e| Err::custom(format!("invalid point: {}", e)))?
                } else if compressed_len * 2 == v.len() {
                    hex::decode_to_slice(v, &mut buffer[..compressed_len])
                        .map_err(|_| Err::custom("malformed hex encoding"))?;
                    Point::from_bytes(&buffer[..compressed_len])
                        .map_err(|e| Err::custom(format!("invalid point: {}", e)))?
                } else {
                    return Err(Err::custom("invalid point"));
                };

                Ok(point)
            }
        }

        if !deserializer.is_human_readable() {
            deserializer
                .deserialize_bytes(PointBytesVisitor(PhantomData))
                .map(PointFromBytes)
        } else {
            deserializer
                .deserialize_str(PointBytesVisitor(PhantomData))
                .map(PointFromBytes)
        }
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
        let is_human_readable = serializer.is_human_readable();
        let mut s = serializer.serialize_struct("Scalar", 2)?;
        s.serialize_field("curve", E::CURVE_NAME)?;
        if !is_human_readable {
            s.serialize_field(
                "scalar",
                // Serializes bytes efficiently
                Bytes::new(&self.to_bytes()),
            )?;
        } else {
            s.serialize_field("scalar", &hex::encode(&*self.to_bytes()))?;
        }
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

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if let Some(size) = seq.size_hint() {
                    if size != 2 {
                        return Err(A::Error::invalid_length(size, &"2"));
                    }
                }
                let _curve_name: CurveNameGuard<E> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::missing_field("curve name"))?;
                let scalar: ScalarFromBytes<E> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::missing_field("scalar value"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("scalar consist of too many fields"));
                }
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

            // serde_json serializes bytes as a sequence of u8, so we need to support this format too
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let seq_len_hint = seq.size_hint();
                let expected_len = <E::Scalar as ECScalar>::ScalarLength::USIZE;

                let mut buffer =
                    GenericArray::<u8, <E::Scalar as ECScalar>::ScalarLength>::default();

                for (i, x) in buffer.iter_mut().enumerate() {
                    *x = match seq.next_element()? {
                        Some(b) => b,
                        None => {
                            return Err(A::Error::invalid_length(
                                i,
                                &format!("{} bytes", expected_len).as_str(),
                            ))
                        }
                    };
                }

                // Ensure that there are no other elements in the sequence
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(
                        seq_len_hint.unwrap_or(expected_len + 1),
                        &format!("{} bytes", expected_len).as_str(),
                    ));
                }

                Scalar::from_bytes(buffer.as_slice())
                    .map_err(|_| A::Error::custom("invalid scalar"))
            }

            fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
            where
                Err: Error,
            {
                let expected_len = <E::Scalar as ECScalar>::ScalarLength::USIZE;
                if expected_len * 2 != v.len() {
                    return Err(Err::invalid_length(
                        v.len(),
                        &format!("{}", expected_len * 2).as_str(),
                    ));
                }

                let mut buffer =
                    GenericArray::<u8, <E::Scalar as ECScalar>::ScalarLength>::default();
                hex::decode_to_slice(v, &mut buffer)
                    .map_err(|_| Err::custom("malformed hex encoding"))?;

                Scalar::from_bytes(&buffer).map_err(|_| Err::custom("invalid scalar"))
            }
        }

        if !deserializer.is_human_readable() {
            deserializer
                .deserialize_bytes(ScalarBytesVisitor(PhantomData))
                .map(ScalarFromBytes)
        } else {
            deserializer
                .deserialize_str(ScalarBytesVisitor(PhantomData))
                .map(ScalarFromBytes)
        }
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
    use serde_test::{
        assert_de_tokens, assert_de_tokens_error, assert_tokens, Configure, Token::*,
    };

    use crate::elliptic::curves::*;
    use crate::test_for_all_curves;

    test_for_all_curves!(serializes_deserializes_point);
    fn serializes_deserializes_point<E: Curve>() {
        let random_point = Point::<E>::generator() * Scalar::random();
        for point in [Point::zero(), random_point] {
            println!("Point: {:?}", point);
            let bytes = point.to_bytes(true).to_vec();
            let tokens = [
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
            assert_tokens(&point.compact(), &tokens);
        }
    }

    test_for_all_curves!(serializes_deserializes_scalar);
    fn serializes_deserializes_scalar<E: Curve>() {
        for scalar in [Scalar::<E>::zero(), Scalar::random()] {
            println!("Scalar: {:?}", scalar);
            let bytes = scalar.to_bytes().to_vec();
            let tokens = [
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
            assert_tokens(&scalar.compact(), &tokens);
        }
    }

    test_for_all_curves!(deserializes_point_from_seq_of_bytes);
    fn deserializes_point_from_seq_of_bytes<E: Curve>() {
        let random_point = Point::<E>::generator() * Scalar::random();
        for point in [Point::zero(), random_point] {
            println!("Point: {:?}", point);
            let bytes = point.to_bytes(true);
            let mut tokens = vec![
                Struct {
                    name: "Point",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("point"),
                Seq {
                    len: Option::Some(bytes.len()),
                },
            ];
            tokens.extend(bytes.iter().copied().map(U8));
            tokens.extend_from_slice(&[SeqEnd, StructEnd]);
            assert_de_tokens(&point.compact(), &tokens);
        }
    }

    test_for_all_curves!(deserializes_scalar_from_seq_of_bytes);
    fn deserializes_scalar_from_seq_of_bytes<E: Curve>() {
        for scalar in [Scalar::<E>::zero(), Scalar::random()] {
            println!("Scalar: {:?}", scalar);
            let bytes = scalar.to_bytes();
            let mut tokens = vec![
                Struct {
                    name: "Scalar",
                    len: 2,
                },
                Str("curve"),
                Str(E::CURVE_NAME),
                Str("scalar"),
                Seq {
                    len: Option::Some(bytes.len()),
                },
            ];
            tokens.extend(bytes.iter().copied().map(U8));
            tokens.extend_from_slice(&[SeqEnd, StructEnd]);
            assert_de_tokens(&scalar.compact(), &tokens);
        }
    }

    test_for_all_curves!(deserializes_point_represented_as_seq);
    fn deserializes_point_represented_as_seq<E: Curve>() {
        let point = Point::<E>::generator() * Scalar::random();
        let tokens = [
            Seq {
                len: Option::Some(2),
            },
            Str(E::CURVE_NAME),
            Bytes(point.to_bytes(true).to_vec().leak()),
            SeqEnd,
        ];
        assert_de_tokens(&point.compact(), &tokens);
    }

    test_for_all_curves!(deserializes_scalar_represented_as_seq);
    fn deserializes_scalar_represented_as_seq<E: Curve>() {
        let scalar = Scalar::<E>::random();
        let tokens = [
            Seq {
                len: Option::Some(2),
            },
            Str(E::CURVE_NAME),
            Bytes(scalar.to_bytes().to_vec().leak()),
            SeqEnd,
        ];
        assert_de_tokens(&scalar.compact(), &tokens);
    }

    test_for_all_curves!(serializes_deserializes_point_in_human_readable_format);
    fn serializes_deserializes_point_in_human_readable_format<E: Curve>() {
        let point = Point::<E>::generator() * Scalar::random();
        let tokens = [
            Struct {
                name: "Point",
                len: 2,
            },
            Str("curve"),
            Str(E::CURVE_NAME),
            Str("point"),
            Str(Box::leak(
                hex::encode(&*point.to_bytes(true)).into_boxed_str(),
            )),
            StructEnd,
        ];
        assert_tokens(&point.readable(), &tokens);
    }

    test_for_all_curves!(serializes_deserializes_scalar_in_human_readable_format);
    fn serializes_deserializes_scalar_in_human_readable_format<E: Curve>() {
        let scalar = Scalar::<E>::random();
        let tokens = [
            Struct {
                name: "Scalar",
                len: 2,
            },
            Str("curve"),
            Str(E::CURVE_NAME),
            Str("scalar"),
            Str(Box::leak(hex::encode(&*scalar.to_bytes()).into_boxed_str())),
            StructEnd,
        ];
        assert_tokens(&scalar.readable(), &tokens);
    }

    test_for_all_curves!(doesnt_deserialize_point_from_different_curve);
    fn doesnt_deserialize_point_from_different_curve<E: Curve>() {
        let tokens = [
            Struct {
                name: "Point",
                len: 2,
            },
            Str("curve"),
            Str("%not_existing%"),
        ];
        assert_de_tokens_error::<Point<E>>(
            &tokens,
            &format!(
                "belongs to %not_existing% curve, expected {} curve",
                E::CURVE_NAME
            ),
        )
    }

    test_for_all_curves!(doesnt_deserialize_scalar_from_different_curve);
    fn doesnt_deserialize_scalar_from_different_curve<E: Curve>() {
        let tokens = [
            Struct {
                name: "Scalar",
                len: 2,
            },
            Str("curve"),
            Str("%not_existing%"),
        ];
        assert_de_tokens_error::<Scalar<E>>(
            &tokens,
            &format!(
                "belongs to %not_existing% curve, expected {} curve",
                E::CURVE_NAME
            ),
        )
    }

    test_for_all_curves!(supports_serde_json);
    fn supports_serde_json<E: Curve>() {
        let random_scalar = Scalar::<E>::random();
        let scalar_json = serde_json::to_string(&random_scalar).unwrap();
        let deserialized_scalar = serde_json::from_str(&scalar_json).unwrap();
        assert_eq!(random_scalar, deserialized_scalar);

        let random_point = Point::generator() * random_scalar;
        let point_json = serde_json::to_string(&random_point).unwrap();
        let deserialized_point: Point<E> = serde_json::from_str(&point_json).unwrap();
        assert_eq!(random_point, deserialized_point);
    }
}
