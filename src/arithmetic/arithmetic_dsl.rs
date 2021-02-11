use super::BigInt;

pub trait Modular<M> {
    fn modulus(self, m: M) -> BigInt;
}
