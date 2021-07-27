/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

/// This is an implementation of string coin tossing of a string, to generate a random string between
///two non-trusting parties. Based on the
/// the protocol and proof analysis  in "How To Simulate It – A Tutorial on the Simulation
/// Proof Technique∗" (<https://eprint.iacr.org/2016/046.pdf>)
pub mod coin_flip_optimal_rounds;

///This is an implementation of a Diffie Hellman Key Exchange.
/// Party1 private key is "x",
/// Party2 private key is "y",
/// The shared secret is Q = xyG
pub mod dh_key_exchange;

///This is an implementation of a Diffie Hellman Key Exchange.
/// Party1 private key is "x",
/// Party2 private key is "y",
///protocol:
/// party1 sends a commitmemt to P1 = xG a commitment to a proof of knowledge of x
/// party2 sends P2 and a proof of knowledge of y
/// party1 verifies party2 proof decommit to P1 and  to the PoK
/// party2 verifies party1 proof
/// the shared secret is Q = xyG
/// reference can be found in protocol 3.1 step 1 - 3(b) in the paper <https://eprint.iacr.org/2017/552.pdf>
pub mod dh_key_exchange_variant_with_pok_comm;
