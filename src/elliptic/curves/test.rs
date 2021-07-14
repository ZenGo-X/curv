#![allow(non_snake_case)]

use std::iter;

use rand::{rngs::OsRng, Rng};

use crate::arithmetic::*;
use crate::test_for_all_curves;

use super::traits::*;

test_for_all_curves!(valid_zero_point);
fn valid_zero_point<E: Curve>() {
    let zero = E::Scalar::zero();
    assert!(zero.is_zero());
    assert_eq!(zero, E::Scalar::zero());
}

test_for_all_curves!(zero_point_arithmetic);
fn zero_point_arithmetic<E: Curve>() {
    let zero_point = E::Point::zero();
    let point = E::Point::generator().scalar_mul(&E::Scalar::random());

    assert_eq!(zero_point.add_point(&point), point, "O + P = P");
    assert_eq!(point.add_point(&zero_point), point, "P + O = P");

    let point_neg = point.neg_point();
    assert!(point.add_point(&point_neg).is_zero(), "P + (-P) = O");
    assert!(point.sub_point(&point).is_zero(), "P - P = O");

    let zero_scalar = E::Scalar::zero();
    assert!(point.scalar_mul(&zero_scalar).is_zero(), "P * 0 = O");
    let scalar = E::Scalar::random();
    assert!(zero_point.scalar_mul(&scalar).is_zero(), "O * s = O")
}

test_for_all_curves!(scalar_modulo_curve_order);
fn scalar_modulo_curve_order<E: Curve>() {
    let n = E::Scalar::group_order();
    let s = E::Scalar::from_bigint(n);
    assert!(s.is_zero());

    let s = E::Scalar::from_bigint(&(n + 1));
    assert_eq!(s, E::Scalar::from_bigint(&BigInt::from(1)));
}

test_for_all_curves!(zero_scalar_arithmetic);
fn zero_scalar_arithmetic<E: Curve>() {
    let s = E::Scalar::random();
    let z = E::Scalar::zero();
    assert!(s.mul(&z).is_zero());
    assert!(z.mul(&s).is_zero());
    assert_eq!(s.add(&z), s);
    assert_eq!(z.add(&s), s);
}

test_for_all_curves!(point_addition_multiplication);
fn point_addition_multiplication<E: Curve>() {
    let point = E::Point::generator().scalar_mul(&E::Scalar::random());
    assert!(!point.is_zero(), "G * s != O");

    let addition = iter::successors(Some(point.clone()), |p| Some(p.add_point(&point)))
        .take(10)
        .collect::<Vec<_>>();
    let multiplication = (1..=10)
        .map(|i| E::Scalar::from_bigint(&BigInt::from(i)))
        .map(|s| point.scalar_mul(&s))
        .collect::<Vec<_>>();
    assert_eq!(addition, multiplication);
}

test_for_all_curves!(serialize_deserialize);
fn serialize_deserialize<E: Curve>() {
    let point = <E::Point as ECPoint>::generator().scalar_mul(&E::Scalar::random());
    let bytes = point
        .serialize(true)
        .expect("point has coordinates => must be serializable");
    let deserialized = <E::Point as ECPoint>::deserialize(&bytes).unwrap();
    assert_eq!(point, deserialized);

    let bytes = point
        .serialize(false)
        .expect("point has coordinates => must be serializable");
    let deserialized = E::Point::deserialize(&bytes).unwrap();
    assert_eq!(point, deserialized);
}

test_for_all_curves!(generator_mul_curve_order_is_zero);
fn generator_mul_curve_order_is_zero<E: Curve>() {
    let g: &E::Point = ECPoint::generator();
    let n = E::Scalar::group_order() - 1;
    let s = E::Scalar::from_bigint(&n);
    assert!(g.scalar_mul(&s).add_point(&g).is_zero());
}

test_for_all_curves!(scalar_behaves_the_same_as_bigint);
fn scalar_behaves_the_same_as_bigint<E: Curve>() {
    let mut rng = OsRng;
    let q = E::Scalar::group_order();

    let mut n = BigInt::zero();
    let mut s: E::Scalar = ECScalar::zero();

    for _ in 0..100 {
        let operation = rng.gen_range(0, 4);
        if operation == 0 {
            let n_inv = BigInt::mod_inv(&n, q);
            let s_inv = s.invert().map(|s| s.to_bigint());

            assert_eq!(
                s_inv,
                n_inv,
                "{}^-1 = {} (got {})",
                n,
                n_inv
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or("None".to_string()),
                s_inv
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or("None".to_string()),
            );
        } else {
            let n_was = n.clone();
            let k = BigInt::sample_below(&(q * 2));
            let op;

            match operation {
                1 => {
                    op = "+";
                    n = BigInt::mod_add(&n, &k, q);
                    s.add_assign(&E::Scalar::from_bigint(&k));
                }
                2 => {
                    op = "*";
                    n = BigInt::mod_mul(&n, &k, q);
                    s.mul_assign(&E::Scalar::from_bigint(&k));
                }
                3 => {
                    op = "-";
                    n = BigInt::mod_sub(&n, &k, q);
                    s.sub_assign(&E::Scalar::from_bigint(&k));
                }
                _ => unreachable!(),
            }

            assert_eq!(
                s.to_bigint(),
                n.modulus(q),
                "{} {} {} = {} (got {})",
                n_was,
                op,
                k,
                n,
                s.to_bigint()
            );
        }
    }
}

test_for_all_curves!(from_coords_produces_the_same_point);
fn from_coords_produces_the_same_point<E: Curve>() {
    let s: E::Scalar = ECScalar::random();
    println!("s={}", s.to_bigint());

    let p: E::Point = <E::Point as ECPoint>::generator().scalar_mul(&s);
    if let Some(coords) = p.coords() {
        let p2: E::Point = ECPoint::from_coords(&coords.x, &coords.y).unwrap();
        assert_eq!(p, p2);
    }
}

test_for_all_curves!(test_point_addition);
fn test_point_addition<E: Curve>() {
    let a: E::Scalar = ECScalar::random();
    let b: E::Scalar = ECScalar::random();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);
    let a_plus_b = a.add(&b);
    let a_plus_b_G: E::Point = ECPoint::generator_mul(&a_plus_b);

    assert_eq!(aG.add_point(&bG), a_plus_b_G);
}

test_for_all_curves!(test_point_subtraction);
fn test_point_subtraction<E: Curve>() {
    let a: E::Scalar = ECScalar::random();
    let b: E::Scalar = ECScalar::random();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);
    let a_minus_b = a.sub(&b);
    let a_minus_b_G: E::Point = ECPoint::generator_mul(&a_minus_b);

    assert_eq!(aG.sub_point(&bG), a_minus_b_G);
}

test_for_all_curves!(test_multiplication_point_at_scalar);
fn test_multiplication_point_at_scalar<E: Curve>() {
    let a: E::Scalar = ECScalar::random();
    let b: E::Scalar = ECScalar::random();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let abG: E::Point = aG.scalar_mul(&b);
    let a_mul_b = a.mul(&b);
    let a_mul_b_G: E::Point = ECPoint::generator_mul(&a_mul_b);

    assert_eq!(abG, a_mul_b_G);
}

test_for_all_curves!(scalar_invert);
fn scalar_invert<E: Curve>() {
    let n: E::Scalar = ECScalar::random();
    if n.is_zero() {
        // Scalar is zero => restart the test
        scalar_invert::<E>()
    }

    let n_inv = n.invert().unwrap();
    assert_eq!(n.mul(&n_inv), ECScalar::from_bigint(&BigInt::one()))
}

test_for_all_curves!(zero_scalar_invert);
fn zero_scalar_invert<E: Curve>() {
    let n: E::Scalar = ECScalar::zero();
    let n_inv = n.invert();
    assert!(n_inv.is_none())
}
