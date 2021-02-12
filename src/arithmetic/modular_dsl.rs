use num_traits::Signed;

use super::{BigInt, Wrap};

mod add;
mod mul;
mod neg;
mod pow;
mod sub;

pub use add::*;
pub use mul::*;
pub use neg::*;
pub use pow::*;
pub use sub::*;

pub trait Modular {
    fn modulus(self, m: &BigInt) -> BigInt;
}

impl Modular for BigInt {
    fn modulus(self, m: &BigInt) -> Self {
        let n = self.into_inner() % m.inner_ref();
        if n.is_negative() {
            (m.inner_ref() + n).wrap()
        } else {
            n.wrap()
        }
    }
}
