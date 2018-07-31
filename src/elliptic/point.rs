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

use arithmetic::traits::Converter;
use BigInt;

/// A simple Point defined by x and y
#[derive(PartialEq, Debug)]
pub struct Point {
    pub x: BigInt,
    pub y: BigInt,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RawPoint {
    pub x: String,
    pub y: String,
}

impl From<Point> for RawPoint {
    fn from(point: Point) -> Self {
        RawPoint {
            x: point.x.to_hex(),
            y: point.y.to_hex(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BigInt;
    use super::Point;
    use super::RawPoint;

    use serde_json;

    #[test]
    fn equality_test() {
        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };
        let p2 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };
        assert_eq!(p1, p2);

        let p3 = Point {
            x: BigInt::zero(),
            y: BigInt::one(),
        };
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_serialization() {
        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };

        let s = serde_json::to_string(&RawPoint::from(p1)).expect("Failed in serialization");
        assert_eq!(s, "{\"x\":\"1\",\"y\":\"0\"}");
    }

    #[test]
    fn test_deserialization() {
        let sp1 = "{\"x\":\"1\",\"y\":\"0\"}";
        let rp1: RawPoint = serde_json::from_str(&sp1).expect("Failed in serialization");

        let p1 = Point {
            x: BigInt::one(),
            y: BigInt::zero(),
        };

        assert_eq!(rp1, RawPoint::from(p1));
    }
}
