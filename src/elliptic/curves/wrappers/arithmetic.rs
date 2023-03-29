use std::ops;

use crate::elliptic::curves::traits::*;

use super::*;

macro_rules! matrix {
    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:expr,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(r_<$($l:lifetime),*> $lhs_ref:ty, $rhs:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs> for $lhs_ref {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs) -> Self::Output {
                let p = self.as_raw().$point_fn(rhs.as_raw());
                $output_new(p)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:expr,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(_r<$($l:lifetime),*> $lhs:ty, $rhs_ref:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs_ref> for $lhs {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs_ref) -> Self::Output {
                let p = rhs.as_raw().$point_fn(self.as_raw());
                $output_new(p)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:expr,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(o_<$($l:lifetime),*> $lhs_owned:ty, $rhs:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs> for $lhs_owned {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs) -> Self::Output {
                let mut raw = self.into_raw();
                raw.$point_assign_fn(rhs.as_raw());
                $output_new(raw)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:expr,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {(_o<$($l:lifetime),*> $lhs:ty, $rhs_owned:ty), $($rest:tt)*}
    ) => {
        impl<$($l,)* E: Curve> ops::$trait<$rhs_owned> for $lhs {
            type Output = $output;
            fn $trait_fn(self, rhs: $rhs_owned) -> Self::Output {
                let mut raw = rhs.into_raw();
                raw.$point_assign_fn(self.as_raw());
                $output_new(raw)
            }
        }
        matrix!{
            trait = $trait,
            trait_fn = $trait_fn,
            output = $output,
            output_new = $output_new,
            point_fn = $point_fn,
            point_assign_fn = $point_assign_fn,
            pairs = {$($rest)*}
        }
    };

    (
        trait = $trait:ident,
        trait_fn = $trait_fn:ident,
        output = $output:ty,
        output_new = $output_new:expr,
        point_fn = $point_fn:ident,
        point_assign_fn = $point_assign_fn:ident,
        pairs = {}
    ) => {
        // happy termination
    };
}

fn addition_of_two_points<E: Curve>(result: E::Point) -> Point<E> {
    // Safety: addition of two points of group order is always either a zero point or point of group
    // order: `A + B = aG + bG = (a + b)G`
    unsafe { Point::from_raw_unchecked(result) }
}

matrix! {
    trait = Add,
    trait_fn = add,
    output = Point<E>,
    output_new = addition_of_two_points,
    point_fn = add_point,
    point_assign_fn = add_point_assign,
    pairs = {
        (o_<> Point<E>, Point<E>), (o_<> Point<E>, &Point<E>),
        (o_<> Point<E>, Generator<E>),

        (_o<> &Point<E>, Point<E>), (r_<> &Point<E>, &Point<E>),
        (r_<> &Point<E>, Generator<E>),

        (_o<> Generator<E>, Point<E>), (r_<> Generator<E>, &Point<E>),
        (r_<> Generator<E>, Generator<E>),
    }
}

fn subtraction_of_two_point<E: Curve>(result: E::Point) -> Point<E> {
    // Safety: subtraction of two points of group order is always either a zero point or point of group
    // order: `A - B = aG - bG = (a - b)G`
    unsafe { Point::from_raw_unchecked(result) }
}

matrix! {
    trait = Sub,
    trait_fn = sub,
    output = Point<E>,
    output_new = subtraction_of_two_point,
    point_fn = sub_point,
    point_assign_fn = sub_point_assign,
    pairs = {
        (o_<> Point<E>, Point<E>), (o_<> Point<E>, &Point<E>),
        (o_<> Point<E>, Generator<E>),

        (r_<> &Point<E>, Point<E>), (r_<> &Point<E>, &Point<E>),
        (r_<> &Point<E>, Generator<E>),

        (r_<> Generator<E>, Point<E>), (r_<> Generator<E>, &Point<E>),
        (r_<> Generator<E>, Generator<E>),
    }
}

fn multiplication_of_point_at_scalar<E: Curve>(result: E::Point) -> Point<E> {
    // Safety: multiplication of point of group order at a scalar is always either a zero point or
    // point of group order: `kA = kaG`
    unsafe { Point::from_raw_unchecked(result) }
}

matrix! {
    trait = Mul,
    trait_fn = mul,
    output = Point<E>,
    output_new = multiplication_of_point_at_scalar,
    point_fn = scalar_mul,
    point_assign_fn = scalar_mul_assign,
    pairs = {
        (o_<> Point<E>, Scalar<E>), (o_<> Point<E>, &Scalar<E>),
        (r_<> &Point<E>, Scalar<E>), (r_<> &Point<E>, &Scalar<E>),

        (_o<> Scalar<E>, Point<E>), (_o<> &Scalar<E>, Point<E>),
        (_r<> Scalar<E>, &Point<E>), (_r<> &Scalar<E>, &Point<E>),
    }
}

matrix! {
    trait = Add,
    trait_fn = add,
    output = Scalar<E>,
    output_new = Scalar::from_raw,
    point_fn = add,
    point_assign_fn = add_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, &Scalar<E>),
        (_o<> &Scalar<E>, Scalar<E>), (r_<> &Scalar<E>, &Scalar<E>),
    }
}

matrix! {
    trait = Sub,
    trait_fn = sub,
    output = Scalar<E>,
    output_new = Scalar::from_raw,
    point_fn = sub,
    point_assign_fn = sub_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, &Scalar<E>),
        (r_<> &Scalar<E>, Scalar<E>), (r_<> &Scalar<E>, &Scalar<E>),
    }
}

matrix! {
    trait = Mul,
    trait_fn = mul,
    output = Scalar<E>,
    output_new = Scalar::from_raw,
    point_fn = mul,
    point_assign_fn = mul_assign,
    pairs = {
        (o_<> Scalar<E>, Scalar<E>), (o_<> Scalar<E>, &Scalar<E>),
        (_o<> &Scalar<E>, Scalar<E>), (r_<> &Scalar<E>, &Scalar<E>),
    }
}

impl<E: Curve> ops::Mul<&Scalar<E>> for Generator<E> {
    type Output = Point<E>;
    fn mul(self, rhs: &Scalar<E>) -> Self::Output {
        Point::from_raw(E::Point::generator_mul(rhs.as_raw())).expect(
            "generator multiplied by scalar is always a point of group order or a zero point",
        )
    }
}

impl<E: Curve> ops::Mul<Scalar<E>> for Generator<E> {
    type Output = Point<E>;
    fn mul(self, rhs: Scalar<E>) -> Self::Output {
        self.mul(&rhs)
    }
}

impl<E: Curve> ops::Mul<Generator<E>> for &Scalar<E> {
    type Output = Point<E>;
    fn mul(self, rhs: Generator<E>) -> Self::Output {
        rhs.mul(self)
    }
}

impl<E: Curve> ops::Mul<Generator<E>> for Scalar<E> {
    type Output = Point<E>;
    fn mul(self, rhs: Generator<E>) -> Self::Output {
        rhs.mul(self)
    }
}

impl<E: Curve> ops::Neg for Scalar<E> {
    type Output = Scalar<E>;

    fn neg(self) -> Self::Output {
        Scalar::from_raw(self.as_raw().neg())
    }
}

impl<E: Curve> ops::Neg for &Scalar<E> {
    type Output = Scalar<E>;

    fn neg(self) -> Self::Output {
        Scalar::from_raw(self.as_raw().neg())
    }
}

impl<E: Curve> ops::Neg for Point<E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.as_raw().neg_point())
            .expect("neg must not produce point of different order")
    }
}

impl<E: Curve> ops::Neg for &Point<E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.as_raw().neg_point())
            .expect("neg must not produce point of different order")
    }
}

impl<E: Curve> ops::Neg for Generator<E> {
    type Output = Point<E>;

    fn neg(self) -> Self::Output {
        Point::from_raw(self.as_raw().neg_point())
            .expect("neg must not produce point of different order")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! assert_operator_defined_for {
        (
            assert_fn = $assert_fn:ident,
            lhs = {},
            rhs = {$($rhs:ty),*},
        ) => {
            // Corner case
        };
        (
            assert_fn = $assert_fn:ident,
            lhs = {$lhs:ty $(, $lhs_tail:ty)*},
            rhs = {$($rhs:ty),*},
        ) => {
            assert_operator_defined_for! {
                assert_fn = $assert_fn,
                lhs = $lhs,
                rhs = {$($rhs),*},
            }
            assert_operator_defined_for! {
                assert_fn = $assert_fn,
                lhs = {$($lhs_tail),*},
                rhs = {$($rhs),*},
            }
        };
        (
            assert_fn = $assert_fn:ident,
            lhs = $lhs:ty,
            rhs = {$($rhs:ty),*},
        ) => {
            $($assert_fn::<E, $lhs, $rhs>());*
        };
    }

    /// Function asserts that P2 can be added to P1 (ie. P1 + P2) and result is Point.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_addition_defined<E, P1, P2>()
    where
        P1: ops::Add<P2, Output = Point<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_addition_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_addition_defined,
                lhs = {Point<E>, &Point<E>, Generator<E>},
                rhs = {Point<E>, &Point<E>, Generator<E>},
            }
        }
    }

    /// Function asserts that P2 can be subtracted from P1 (ie. P1 - P2) and result is Point.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_subtraction_defined<E, P1, P2>()
    where
        P1: ops::Sub<P2, Output = Point<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_subtraction_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_subtraction_defined,
                lhs = {Point<E>, &Point<E>, Generator<E>},
                rhs = {Point<E>, &Point<E>, Generator<E>},
            }
        }
    }

    /// Function asserts that M can be multiplied by N (ie. M * N) and result is Point.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_point_multiplication_defined<E, M, N>()
    where
        M: ops::Mul<N, Output = Point<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_point_multiplication_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_point_multiplication_defined,
                lhs = {Point<E>, &Point<E>, Generator<E>},
                rhs = {Scalar<E>, &Scalar<E>},
            }

            // and vice-versa

            assert_operator_defined_for! {
                assert_fn = assert_point_multiplication_defined,
                lhs = {Scalar<E>, &Scalar<E>},
                rhs = {Point<E>, &Point<E>, Generator<E>},
            }
        }
    }

    /// Function asserts that S2 can be added to S1 (ie. S1 + S2) and result is Scalar.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_addition_defined<E, S1, S2>()
    where
        S1: ops::Add<S2, Output = Scalar<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_addition_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_addition_defined,
                lhs = {Scalar<E>, Scalar<E>},
                rhs = {Scalar<E>, Scalar<E>},
            }
        }
    }

    /// Function asserts that S2 can be subtracted from S1 (ie. S1 - S2) and result is Scalar.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_subtraction_defined<E, S1, S2>()
    where
        S1: ops::Sub<S2, Output = Scalar<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_subtraction_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_subtraction_defined,
                lhs = {Scalar<E>, Scalar<E>},
                rhs = {Scalar<E>, Scalar<E>},
            }
        }
    }

    /// Function asserts that S1 can be multiplied by S2 (ie. S1 * S2) and result is Scalar.
    /// If any condition doesn't meet, function won't compile.
    #[allow(dead_code)]
    fn assert_scalars_multiplication_defined<E, S1, S2>()
    where
        S1: ops::Mul<S2, Output = Scalar<E>>,
        E: Curve,
    {
        // no-op
    }

    #[test]
    fn test_scalars_multiplication_defined() {
        fn _curve<E: Curve>() {
            assert_operator_defined_for! {
                assert_fn = assert_scalars_multiplication_defined,
                lhs = {Scalar<E>, Scalar<E>},
                rhs = {Scalar<E>, Scalar<E>},
            }
        }
    }
}
