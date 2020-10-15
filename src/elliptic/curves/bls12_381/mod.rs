#[cfg(any(feature = "ec_g1", feature = "ec_bls12_381"))]
pub mod g1;
#[cfg(any(feature = "ec_g2", feature = "ec_bls12_381"))]
pub mod g2;
#[cfg(feature = "ec_bls12_381")]
pub mod gt;
