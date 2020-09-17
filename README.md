[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.com/ZenGo-X/curv.svg?branch=master)](https://travis-ci.com/KZen-networks/curv)

Curv
=====================================
Curv contains an extremly simple interface to onboard new elliptic curves. 
Use this library for general purpose elliptic curve cryptography. 

The library has a built in support for some useful operations/primitives such as verifiable secret sharing, commitment schemes, zero knowledge proofs, and simple two party protocols such as ECDH and coin flip. The library comes with serialize/deserialize support to be used in higher level code to implement networking. 

### Currently Supported Elliptic Curves  

|        Curve         |   low level library    |    curve description       |     
|-------------------------------|------------------------|------------------------|
|    **Secp256k1**    |        [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)            |      [bitcoin wiki](https://en.bitcoin.it/wiki/Secp256k1)           |     
|    **Ed25519**    |        [cryptoxide](https://github.com/typed-io/cryptoxide/blob/master/src/curve25519.rs)            |      [BDLSY11](https://ed25519.cr.yp.to/ed25519-20110926.pdf)           |      
|    **Jubjub**    |        [librustzcash](https://github.com/zcash/librustzcash)            |      [what is jubjub](https://z.cash/technology/jubjub/)          |     
|    **Ristretto**    |        [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)            |     [ristretto group](https://ristretto.group/)           |      
|    **BLS12-381**    |        [bls12-381](https://crates.io/crates/bls12_381)            |     [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)           |     

### Security  
The library was audited by [Kudelski security](https://www.kudelskisecurity.com/) on Feb19. The report can be found [here](https://github.com/KZen-networks/curv/tree/master/audit). No critical issue were found and all issues found were fixed.

The code was reviewed independently by few other cryptographers. Special thanks goes to [Claudio Orlandi](http://cs.au.dk/~orlandi/) from Aarhus University. 

In general security of the library is strongly dependent on the security of the low level libraries used. We chose only libraries that are used as part of other big projects and went through heavy audit/review. 

The library is not immune to side channel attacks but considerable effort was given to try and catch as many such attacks as possible (see audit report). 

### Build
By default `cargo build` will build the library only for `BigInt` (used for example in [rust-paillier](https://github.com/KZen-networks/rust-paillier)). To add opertions for one of the elliptic curves 
a feature must be specified:
- `cargo build --features=ec_secp256k1` for secp256k1
- `cargo build --features=ec_ed25519` for ed25519
- `cargo build --features=ec_jubjub` for jubjub
- `cargo build --features=ec_ristretto` for ristretto
- `cargo build --features=ec_bls12_381` for bls12-381 using G1 as group element

### Examples
The library includes some basic examples to get you going. To run them: 
`cargo run --example EXAMPLE_NAME --features CURVE_NAME`
for example: `cargo run --example proof_of_knowledge_of_dlog --features ec_jubjub`

### Docs 
Docs are built per elliptic curve, use `cargo doc --no-deps --features CURVE_NAME`.
for example: `cargo doc --no-deps --features ec_ed25519`

### Adding New Elliptic Curve
To add support for new elliptic curve simply fill in the `ECScalar` and `ECPoint` [traits](https://github.com/KZen-networks/curv/blob/master/src/elliptic/curves/traits.rs). 

### License
Curv is released under the terms of the MIT license. See [LICENSE](LICENSE) for more information.


### Development Process
We use several methods to communicate: You can open an issue, [reach out](mailto:github@kzencorp.com) by mail or join ZenGo X [Telegram]( https://t.me/zengo_x) for discussions on code and research. Changes are to be submitted as pull requests.

### Contact
For any questions, feel free to [email us](mailto:github@kzencorp.com).
