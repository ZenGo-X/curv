//pub use crate::elliptic::curves::secp256_k1::FE;

// jubjub : https://z.cash/technology/jubjub/

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

#[macro_use]
extern crate serde_derive;

pub mod elliptic;

#[cfg(any(feature = "ec_g1",feature = "ec_bls12_381"))]
pub use crate::elliptic::curves::bls12_381::g1::*;

#[cfg(feature = "ec_g2")]
pub use crate::elliptic::curves::bls12_381::g2::*;


#[cfg(feature = "ec_bls12_381")]
pub use crate::cryptographic_primitives::pairing::*;



#[cfg(feature = "rust-gmp")]
pub mod arithmetic;

pub mod cryptographic_primitives;
pub use crate::arithmetic::big_gmp::BigInt;

fn main(){

    //test_serde();

}


