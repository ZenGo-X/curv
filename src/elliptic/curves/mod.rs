/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

extern crate rand;

#[cfg(feature = "cryptoxide")]
extern crate cryptoxide;
#[cfg(feature = "curve25519-dalek")]
extern crate curve25519_dalek;
#[cfg(feature = "pairing")]
extern crate pairing;
#[cfg(feature = "sapling-crypto")]
extern crate sapling_crypto;
#[cfg(feature = "secp256k1")]
extern crate secp256k1;

#[cfg(feature = "curvejubjub")]
pub mod curve_jubjub;
#[cfg(feature = "curveristretto")]
pub mod curve_ristretto;
#[cfg(feature = "cryptoxide")]
pub mod ed25519;
#[cfg(feature = "secp256k1")]
pub mod secp256_k1;

pub mod traits;
