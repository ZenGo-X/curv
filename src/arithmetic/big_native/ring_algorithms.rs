// Taken from: https://gitlab.com/Toru3/ring-algorithm/-/blob/c4eaf606e88cb62cf87df98c99f923b253ad976a/src/lib.rs
// Original code is licensed under terms of: MIT OR Apache-2.0

use num_bigint::Sign;
use num_traits::Signed;

use crate::arithmetic::{One, Zero};

use super::BigInt;

fn leading_unit(n: &BigInt) -> BigInt {
    match n.num.sign() {
        Sign::Minus => -BigInt::one(),
        _ => BigInt::one(),
    }
}

fn abs(n: &BigInt) -> BigInt {
    BigInt { num: n.num.abs() }
}

/// Extended euclidian algorithm with normalize
pub fn normalized_extended_euclidian_algorithm(x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
    let lc_x = leading_unit(&x);
    let lc_y = leading_unit(&y);
    let mut old = (abs(x), &BigInt::one() / &lc_x, BigInt::zero());
    let mut now = (abs(y), BigInt::zero(), &BigInt::one() / &lc_y);
    while !now.0.is_zero() {
        let q = &old.0 / &now.0;
        let r = &old.0 % &now.0;
        let lc_r = leading_unit(&r);
        let new = (
            abs(&r),
            &(&old.1 - &(&q * &now.1)) / &lc_r,
            &(&old.2 - &(&q * &now.2)) / &lc_r,
        );
        old = now;
        now = new;
    }
    old
}

/// Calc inverse in modulo
///
/// calc x ($`ax \equiv 1 \pmod{m}`$)
pub fn modulo_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (gcd, inv_a, _) = normalized_extended_euclidian_algorithm(a, m);
    if gcd.is_one() {
        Some(inv_a)
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic::Modulo;

    #[test]
    fn test_gcd() {
        let gcd = |a, b| normalized_extended_euclidian_algorithm(&a, &b).0;
        assert_eq!(gcd(BigInt::from(0), BigInt::from(0)), BigInt::from(0));
        assert_eq!(gcd(BigInt::from(42), BigInt::from(0)), BigInt::from(42));
        assert_eq!(gcd(BigInt::from(0), BigInt::from(42)), BigInt::from(42));
        assert_eq!(gcd(BigInt::from(64), BigInt::from(58)), BigInt::from(2));
        assert_eq!(gcd(BigInt::from(97), BigInt::from(89)), BigInt::from(1));
    }

    #[test]
    fn test_mod_inv() {
        // not exists inverse
        assert_eq!(check_mod_inv(&BigInt::from(0), &BigInt::from(0)), false);
        assert_eq!(check_mod_inv(&BigInt::from(42), &BigInt::from(0)), false);
        assert_eq!(check_mod_inv(&BigInt::from(0), &BigInt::from(42)), false);
        assert_eq!(check_mod_inv(&BigInt::from(64), &BigInt::from(58)), false);
        // exists inverse
        assert_eq!(check_mod_inv(&BigInt::from(97), &BigInt::from(89)), true);
        assert_eq!(check_mod_inv(&BigInt::from(7), &BigInt::from(15)), true);
        assert_eq!(check_mod_inv(&BigInt::from(42), &BigInt::from(55)), true);
        assert_eq!(check_mod_inv(&BigInt::from(15), &BigInt::from(64)), true);
    }

    fn check_mod_inv(a: &BigInt, b: &BigInt) -> bool {
        match modulo_inverse(a, b) {
            Some(c) => {
                assert_eq!(BigInt::mod_mul(a, &c, b), BigInt::one());
                true
            }
            None => false,
        }
    }
}
