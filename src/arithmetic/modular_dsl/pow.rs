use std::ops;

use super::{BigInt, Modular, Wrap};

pub trait ModularPow {
    fn pow(self, e: &BigInt) -> Pow<Self>
    where
        Self: Sized;
}

impl<N> ModularPow for N
where
    N: Modular,
{
    fn pow(self, e: &BigInt) -> Pow<Self> {
        Pow { n: self, e }
    }
}

pub struct Pow<'a, N> {
    n: N,
    e: &'a BigInt,
}

impl<'a, N> Modular for Pow<'a, N>
where
    N: Modular,
{
    fn modulus(self, m: &BigInt) -> BigInt {
        self.n
            .modulus(m)
            .into_inner()
            .modpow(self.e.inner_ref(), m.inner_ref())
            .wrap()
    }
}
