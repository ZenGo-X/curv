use std::ops;

use super::{BigInt, Modular, Wrap};

pub struct Mul<L, R> {
    pub(super) lhs: L,
    pub(super) rhs: R,
}

impl<L, R> Modular for Mul<L, R>
where
    L: Modular,
    R: Modular,
{
    fn modulus(self, m: &BigInt) -> BigInt {
        let lhs = self.lhs.modulus(m).into_inner();
        let rhs = self.rhs.modulus(m).into_inner();
        (lhs * rhs).wrap().modulus(m)
    }
}

impl<M> ops::Mul<M> for BigInt
where
    M: Modular,
{
    type Output = Mul<Self, M>;
    fn mul(self, rhs: M) -> Self::Output {
        Mul { lhs: self, rhs }
    }
}

impl<'a, M> ops::Mul<M> for &'a BigInt
where
    M: Modular,
{
    type Output = Mul<&'a BigInt, M>;
    fn mul(self, rhs: M) -> Self::Output {
        Mul { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Add<C> for Mul<A, B>
where
    C: Modular,
{
    type Output = super::Add<Mul<A, B>, C>;
    fn add(self, rhs: C) -> Self::Output {
        super::Add { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Sub<C> for Mul<A, B>
where
    C: Modular,
{
    type Output = super::Sub<Mul<A, B>, C>;
    fn sub(self, rhs: C) -> Self::Output {
        super::Sub { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Mul<C> for Mul<A, B>
where
    C: Modular,
{
    type Output = Mul<Mul<A, B>, C>;
    fn mul(self, rhs: C) -> Self::Output {
        Mul { lhs: self, rhs }
    }
}

impl<L, R> ops::Neg for Mul<L, R> {
    type Output = super::Neg<Mul<L, R>>;
    fn neg(self) -> Self::Output {
        super::Neg(self)
    }
}
