use std::ops;

use super::{BigInt, Modular, Wrap};

pub struct Add<L, R> {
    pub(super) lhs: L,
    pub(super) rhs: R,
}

impl<L, R> Modular for Add<L, R>
where
    L: Modular,
    R: Modular,
{
    fn modulus(self, m: &BigInt) -> BigInt {
        let lhs = self.lhs.modulus(m).into_inner();
        let rhs = self.rhs.modulus(m).into_inner();
        (lhs + rhs).wrap().modulus(m)
    }
}

impl<M> ops::Add<M> for BigInt
where
    M: Modular,
{
    type Output = Add<Self, M>;
    fn add(self, rhs: M) -> Self::Output {
        Add { lhs: self, rhs }
    }
}

impl<'a, M> ops::Add<M> for &'a BigInt
where
    M: Modular,
{
    type Output = Add<&'a BigInt, M>;
    fn add(self, rhs: M) -> Self::Output {
        Add { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Add<C> for Add<A, B>
where
    C: Modular,
{
    type Output = Add<Add<A, B>, C>;
    fn add(self, rhs: C) -> Self::Output {
        Add { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Sub<C> for Add<A, B>
where
    C: Modular,
{
    type Output = super::Sub<Add<A, B>, C>;
    fn sub(self, rhs: C) -> Self::Output {
        super::Sub { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Mul<C> for Add<A, B>
where
    C: Modular,
{
    type Output = super::Mul<Add<A, B>, C>;
    fn mul(self, rhs: C) -> Self::Output {
        super::Mul { lhs: self, rhs }
    }
}

impl<L, R> ops::Neg for Add<L, R> {
    type Output = super::Neg<Add<L, R>>;
    fn neg(self) -> Self::Output {
        super::Neg(self)
    }
}
