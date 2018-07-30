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

#[derive(Serialize, Deserialize)]
pub struct RawPoint {
    pub x: String,
    pub y: String,
}

impl Point {
    pub fn to_raw(&self) -> RawPoint {
        RawPoint {
            x: self.x.to_hex(),
            y: self.y.to_hex(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BigInt;
    use super::Point;
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

        let s = serde_json::to_string(&p1.to_raw()).expect("Failed in serialization");
        assert_eq!(s, "{\"x\":\"1\",\"y\":\"0\"}");
    }
}
