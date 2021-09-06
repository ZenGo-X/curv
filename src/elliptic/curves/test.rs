#![allow(non_snake_case)]

use std::iter;

use rand::{rngs::OsRng, Rng};

use crate::arithmetic::*;
use crate::elliptic::curves::ed25519::{Ed25519Point, Ed25519Scalar};
use crate::{test_for_all_curves, test_for_ed25519};

use super::traits::*;

fn random_nonzero_scalar<S: ECScalar>() -> S {
    loop {
        let s = S::random();
        if !s.is_zero() {
            break s;
        }
    }
}

test_for_all_curves!(valid_zero_point);
fn valid_zero_point<E: Curve>() {
    let zero = E::Scalar::zero();
    assert!(zero.is_zero());
    assert_eq!(zero, E::Scalar::zero());
}

pub fn check_torsion_safety<E: Curve<Scalar = Ed25519Scalar>>(a: &BigInt, a_torsion_safe: &BigInt) {
    let ec_point: &E::Point = ECPoint::generator();
    let mut torsion_point: Vec<Ed25519Point> = Vec::with_capacity(8);

    // vector points are compressed Y format of curve-dalek's extended torsion point co-ordinates.
    // using deserialize is sufficeint here since no multiplication by 8 are taking place internally to make it an element of subgroup of prime order.
    torsion_point.push(
        ECPoint::deserialize(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap(),
    );
    torsion_point.push(
        Ed25519Point::deserialize(&[
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
        ])
        .unwrap(),
    );

    // a is congruent to a_torsion_safe modulo FE:q()
    assert_eq!(
        a % E::Scalar::group_order(),
        a_torsion_safe % E::Scalar::group_order()
    );

    // a_torsion_safe results to idnetity mod 8.
    let id1: E::Scalar =
        Ed25519Scalar::from_big_int_to_small_torsion_safe(&(a_torsion_safe % BigInt::from(8)));
    assert_eq!(E::Scalar::zero(), id1);

    // Should result in identity when a_torsion_safe is multiplied to a given small torsion point.
    let a_fe_torsion_safe = Ed25519Scalar::from_big_int_to_small_torsion_safe(&a_torsion_safe);
    for i in 0..8 {
        let id = torsion_point[i].scalar_mul(&a_fe_torsion_safe);
        assert_eq!(true, id.is_zero());
    }

    // Should result same value when multiplied to base point in prime order subgroup.
    let a_fe: E::Scalar = E::Scalar::from_bigint(&a);

    assert_eq!(
        ec_point.scalar_mul(&a_fe),
        ec_point.scalar_mul(&a_fe_torsion_safe)
    );
}

test_for_ed25519!(test_torsion_safety);
pub fn test_torsion_safety<E: Curve<Scalar = Ed25519Scalar>>() {
    let a_scalar: [u8; 32] = [
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26,
        0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76,
        0xef, 0x09,
    ];
    let a_big = BigInt::from_bytes(&a_scalar[..]);
    // calculate a_fe_torsion_safe
    let a_fe_torsion_safe: E::Scalar = Ed25519Scalar::from_big_int_to_small_torsion_safe(&a_big);
    check_torsion_safety::<E>(&a_big, &a_fe_torsion_safe.to_bigint());
}

test_for_all_curves!(zero_point_arithmetic);
fn zero_point_arithmetic<E: Curve>() {
    let zero_point = E::Point::zero();
    let point = E::Point::generator().scalar_mul(&random_nonzero_scalar());

    assert_eq!(zero_point.add_point(&point), point, "O + P = P");
    assert_eq!(point.add_point(&zero_point), point, "P + O = P");

    let point_neg = point.neg_point();
    assert!(point.add_point(&point_neg).is_zero(), "P + (-P) = O");
    assert!(point.sub_point(&point).is_zero(), "P - P = O");

    let zero_scalar = E::Scalar::zero();
    assert!(point.scalar_mul(&zero_scalar).is_zero(), "P * 0 = O");
    let scalar = random_nonzero_scalar();
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
    let s: E::Scalar = random_nonzero_scalar();
    let z = E::Scalar::zero();
    assert!(s.mul(&z).is_zero());
    assert!(z.mul(&s).is_zero());
    assert_eq!(s.add(&z), s);
    assert_eq!(z.add(&s), s);
}

test_for_all_curves!(point_addition_multiplication);
fn point_addition_multiplication<E: Curve>() {
    let point = E::Point::generator().scalar_mul(&random_nonzero_scalar());
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

test_for_all_curves!(serialize_deserialize_point);
fn serialize_deserialize_point<E: Curve>() {
    let rand_point = <E::Point as ECPoint>::generator().scalar_mul(&random_nonzero_scalar());
    let zero = E::Point::zero();
    for point in [rand_point, zero] {
        let bytes = point.serialize_compressed();
        let deserialized = <E::Point as ECPoint>::deserialize(bytes.as_ref()).unwrap();
        assert_eq!(point, deserialized);
        let bytes = point.serialize_uncompressed();
        let deserialized = <E::Point as ECPoint>::deserialize(bytes.as_ref()).unwrap();
        assert_eq!(point, deserialized);
    }
}

test_for_all_curves!(zero_point_serialization);
fn zero_point_serialization<E: Curve>() {
    let point: E::Point = ECPoint::zero();
    let bytes = point.serialize_compressed();
    let point_from_compressed: E::Point = ECPoint::deserialize(bytes.as_ref()).unwrap();
    assert_eq!(point, point_from_compressed);

    let bytes = point.serialize_uncompressed();
    let point_from_uncompressed: E::Point = ECPoint::deserialize(bytes.as_ref()).unwrap();
    assert_eq!(point, point_from_uncompressed);
}

test_for_all_curves!(generator_mul_curve_order_is_zero);
fn generator_mul_curve_order_is_zero<E: Curve>() {
    let g: &E::Point = ECPoint::generator();
    let n = E::Scalar::group_order() - 1;
    let s = E::Scalar::from_bigint(&n);
    assert!(g.scalar_mul(&s).add_point(g).is_zero());
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
                    .unwrap_or_else(|| "None".to_string()),
                s_inv
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "None".to_string()),
            );
        } else {
            let n_was = n.clone();
            let k = BigInt::sample_below(&(q * 2));
            let k_s: E::Scalar = ECScalar::from_bigint(&k);
            let op;

            match operation {
                1 => {
                    op = "+";
                    n = BigInt::mod_add(&n, &k, q);

                    let s_no_assign = s.add(&k_s);
                    s.add_assign(&k_s);
                    assert_eq!(s, s_no_assign);
                }
                2 => {
                    op = "*";
                    n = BigInt::mod_mul(&n, &k, q);

                    let s_no_assign = s.mul(&k_s);
                    s.mul_assign(&k_s);
                    assert_eq!(s, s_no_assign);
                }
                3 => {
                    op = "-";
                    n = BigInt::mod_sub(&n, &k, q);

                    let s_no_assign = s.sub(&k_s);
                    s.sub_assign(&k_s);
                    assert_eq!(s, s_no_assign);
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
    if E::CURVE_NAME == "ristretto" {
        // This curve is exception.
        return;
    }
    let s: E::Scalar = random_nonzero_scalar();
    println!("s={}", s.to_bigint());

    let p: E::Point = <E::Point as ECPoint>::generator().scalar_mul(&s);
    let coords = p.coords().unwrap();
    let p2: E::Point = ECPoint::from_coords(&coords.x, &coords.y).unwrap();
    assert_eq!(p, p2);
}

test_for_all_curves!(test_point_addition);
fn test_point_addition<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);
    let a_plus_b = a.add(&b);
    let a_plus_b_G: E::Point = ECPoint::generator_mul(&a_plus_b);

    assert_eq!(aG.add_point(&bG), a_plus_b_G);
}

test_for_all_curves!(test_point_assign_addition);
fn test_point_assign_addition<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);

    let a_plus_b_G_1 = aG.add_point(&bG);
    let a_plus_b_G_2 = {
        let mut aG = aG;
        aG.add_point_assign(&bG);
        aG
    };

    assert_eq!(a_plus_b_G_1, a_plus_b_G_2);
}

test_for_all_curves!(test_point_subtraction);
fn test_point_subtraction<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);
    let a_minus_b = a.sub(&b);
    let a_minus_b_G: E::Point = ECPoint::generator_mul(&a_minus_b);

    assert_eq!(aG.sub_point(&bG), a_minus_b_G);
}

test_for_all_curves!(test_point_assign_subtraction);
fn test_point_assign_subtraction<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let bG: E::Point = ECPoint::generator_mul(&b);

    let a_minus_b_G_1: E::Point = aG.sub_point(&bG);
    let a_minus_b_G_2 = {
        let mut aG = aG;
        aG.sub_point_assign(&bG);
        aG
    };

    assert_eq!(a_minus_b_G_1, a_minus_b_G_2);
}

test_for_all_curves!(test_multiplication_point_at_scalar);
fn test_multiplication_point_at_scalar<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);
    let abG: E::Point = aG.scalar_mul(&b);
    let a_mul_b = a.mul(&b);
    let a_mul_b_G: E::Point = ECPoint::generator_mul(&a_mul_b);

    assert_eq!(abG, a_mul_b_G);
}

test_for_all_curves!(test_assign_multiplication_point_at_scalar);
fn test_assign_multiplication_point_at_scalar<E: Curve>() {
    let a: E::Scalar = random_nonzero_scalar();
    let b: E::Scalar = random_nonzero_scalar();

    let aG: E::Point = ECPoint::generator_mul(&a);

    let abG_1: E::Point = aG.scalar_mul(&b);
    let abG_2 = {
        let mut aG = aG;
        aG.scalar_mul_assign(&b);
        aG
    };

    assert_eq!(abG_1, abG_2);
}

test_for_all_curves!(serialize_deserialize_scalar);
fn serialize_deserialize_scalar<E: Curve>() {
    let rand_point: E::Scalar = random_nonzero_scalar();
    let zero = E::Scalar::zero();
    for scalar in [rand_point, zero] {
        let bytes = scalar.serialize();
        let deserialized = <E::Scalar as ECScalar>::deserialize(bytes.as_ref()).unwrap();
        assert_eq!(scalar, deserialized);
    }
}

test_for_all_curves!(scalar_invert);
fn scalar_invert<E: Curve>() {
    let n: E::Scalar = random_nonzero_scalar();

    let n_inv = n.invert().unwrap();
    assert_eq!(n.mul(&n_inv), ECScalar::from_bigint(&BigInt::one()))
}

test_for_all_curves!(zero_scalar_invert);
fn zero_scalar_invert<E: Curve>() {
    let n: E::Scalar = ECScalar::zero();
    let n_inv = n.invert();
    assert!(n_inv.is_none())
}

test_for_all_curves!(point_negation);
fn point_negation<E: Curve>() {
    let p1 = <E::Point as ECPoint>::generator_mul(&random_nonzero_scalar());
    let p2 = p1.neg_point();
    assert_eq!(p1.add_point(&p2), ECPoint::zero());
}

test_for_all_curves!(point_assign_negation);
fn point_assign_negation<E: Curve>() {
    let p = <E::Point as ECPoint>::generator_mul(&random_nonzero_scalar());
    let p_neg_1 = p.neg_point();
    let p_neg_2 = {
        let mut p = p;
        p.neg_point_assign();
        p
    };
    assert_eq!(p_neg_1, p_neg_2);
}

test_for_all_curves!(scalar_negation);
fn scalar_negation<E: Curve>() {
    let s1: E::Scalar = random_nonzero_scalar();
    let s2 = s1.neg();
    assert_eq!(s1.add(&s2), E::Scalar::zero());
}

test_for_all_curves!(scalar_assign_negation);
fn scalar_assign_negation<E: Curve>() {
    let s: E::Scalar = random_nonzero_scalar();
    let s_neg_1 = s.neg();
    let s_neg_2 = {
        let mut s = s;
        s.neg_assign();
        s
    };
    assert_eq!(s_neg_1, s_neg_2);
}
