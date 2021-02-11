use std::ops;

use super::{BigInt, Modular, Wrap};

pub struct Sub<L, R> {
    pub(super) lhs: L,
    pub(super) rhs: R,
}

impl<L, R> Modular for Sub<L, R>
where
    L: Modular,
    R: Modular,
{
    fn modulus(self, m: &BigInt) -> BigInt {
        let lhs = self.lhs.modulus(m).into_inner();
        let rhs = self.rhs.modulus(m).into_inner();
        if lhs < rhs {
            let c = (rhs - lhs) % m.inner_ref();
            (m.inner_ref() - c).wrap().modulus(m)
        } else {
            (lhs - rhs).wrap().modulus(m)
        }
    }
}

impl<M> ops::Sub<M> for BigInt
where
    M: Modular,
{
    type Output = Sub<Self, M>;
    fn sub(self, rhs: M) -> Self::Output {
        Sub { lhs: self, rhs }
    }
}

impl<'a, M> ops::Sub<M> for &'a BigInt
where
    M: Modular,
{
    type Output = Sub<&'a BigInt, M>;
    fn sub(self, rhs: M) -> Self::Output {
        Sub { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Add<C> for Sub<A, B>
where
    C: Modular,
{
    type Output = super::Add<Sub<A, B>, C>;
    fn add(self, rhs: C) -> Self::Output {
        super::Add { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Sub<C> for Sub<A, B>
where
    C: Modular,
{
    type Output = Sub<Sub<A, B>, C>;
    fn sub(self, rhs: C) -> Self::Output {
        Sub { lhs: self, rhs }
    }
}

impl<A, B, C> ops::Mul<C> for Sub<A, B>
where
    C: Modular,
{
    type Output = super::Mul<Sub<A, B>, C>;
    fn mul(self, rhs: C) -> Self::Output {
        super::Mul { lhs: self, rhs }
    }
}

impl<L, R> ops::Neg for Sub<L, R> {
    type Output = super::Neg<Sub<L, R>>;
    fn neg(self) -> Self::Output {
        super::Neg(self)
    }
}
