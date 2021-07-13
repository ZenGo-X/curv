use std::iter;

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
    assert!(
        bytes.starts_with(&[2]) || bytes.starts_with(&[3]),
        "compressed form must start either with 2 or 3"
    );

    let bytes = point
        .serialize(false)
        .expect("point has coordinates => must be serializable");
    let deserialized = E::Point::deserialize(&bytes).unwrap();
    assert_eq!(point, deserialized);
    assert!(bytes.starts_with(&[4]), "compressed form must start with 4");
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
    let q = E::Scalar::group_order();

    let mut n = BigInt::zero();
    let mut s: E::Scalar = ECScalar::zero();

    for _ in 0..100 {
        let k = BigInt::sample_below(&(q * 2));

        let n_was = n.clone();
        n += &k;
        s.add_assign(&E::Scalar::from_bigint(&k));

        assert_eq!(
            s.to_bigint(),
            n.modulus(q),
            "{} + {} = {} (got {})",
            n_was,
            k,
            n,
            s.to_bigint()
        );
    }
}
