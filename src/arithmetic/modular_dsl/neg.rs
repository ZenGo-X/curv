use std::ops;

use super::{BigInt, Modular, Wrap};

pub struct Neg<N>(pub(super) N);

impl<N> Modular for Neg<N>
where
    N: Modular,
{
    fn modulus(self, m: &BigInt) -> BigInt {
        let n = self.0.modulus(m).into_inner();
        (m.inner_ref() - n).wrap()
    }
}

impl ops::Neg for BigInt {
    type Output = Neg<BigInt>;

    fn neg(self) -> Self::Output {
        Neg(self)
    }
}

impl<'a> ops::Neg for &'a BigInt {
    type Output = Neg<&'a BigInt>;

    fn neg(self) -> Self::Output {
        Neg(self)
    }
}

impl<L, R> ops::Add<R> for Neg<L>
where
    R: Modular,
{
    type Output = super::Add<Neg<L>, R>;
    fn add(self, rhs: R) -> Self::Output {
        super::Add { lhs: self, rhs }
    }
}

impl<L, R> ops::Sub<R> for Neg<L>
where
    R: Modular,
{
    type Output = super::Sub<Neg<L>, R>;
    fn sub(self, rhs: R) -> Self::Output {
        super::Sub { lhs: self, rhs }
    }
}

impl<L, R> ops::Mul<R> for Neg<L>
where
    R: Modular,
{
    type Output = super::Mul<Neg<L>, R>;
    fn mul(self, rhs: R) -> Self::Output {
        super::Mul { lhs: self, rhs }
    }
}

impl<N> ops::Neg for Neg<N> {
    type Output = N;
    fn neg(self) -> N {
        self.0
    }
}
