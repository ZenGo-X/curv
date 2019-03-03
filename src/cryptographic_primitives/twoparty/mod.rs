/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
        (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/
/// This is an implementation of string coin tossing of a string, to generate a random string between
///two non-trusting parties. Based on the
/// the protocol and proof analysis  in "How To Simulate It – A Tutorial on the Simulation
/// Proof Technique∗" (https://eprint.iacr.org/2016/046.pdf)
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
/// reference can be found in protocol 3.1 step 1 - 3(b) in the paper https://eprint.iacr.org/2017/552.pdf
pub mod dh_key_exchange_variant_with_pok_comm;
