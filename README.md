[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.com/KZen-networks/curv.svg?branch=master)](https://travis-ci.com/KZen-networks/curv)

Curv
=====================================
Curv contains an extremly simple interface to onboard new elliptic curves. 
Use this library for general purpose elliptic curve cryptography. 

### Currently Supported Elliptic Curves  

|        Curve         |   low level library    |    curve description       |    blockchain usage examples       |  
|-------------------------------|------------------------|------------------------|------------------------|
|    **Secp256k1**    |        [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)            |      [bitcoin wiki](https://en.bitcoin.it/wiki/Secp256k1)           |      Bitcoin, Ethereum           |
|    **Ed25519**    |        [cryptoxide](https://github.com/typed-io/cryptoxide/blob/master/src/curve25519.rs)            |      [BDLSY11](https://ed25519.cr.yp.to/ed25519-20110926.pdf)           |      Ripple, Tezos, Cardano           |
|    **Jubjub**    |        [librustzcash](https://github.com/zcash/librustzcash)            |      [what is jubjub](https://z.cash/technology/jubjub/)          |      Zcash           |
|    **Ristretto**    |        [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)            |     [ristretto group](https://ristretto.group/)           |      not yet ;)           |


### Currently Supported Operations 
* **Hash Functions**: SHA256, SHA512, HMAC-SHA512, Merkle-Tree
* **Commitment Schemes**: Hash based, Pedersen
* **Secret Sharing**: Feldman VSS
* **Sigma Protocols:** 
  * Proof of knowledge of EC-DLog
  * Proof of membership of EC-DDH
  * Proof of correct Pedersen
  * Proof of correct Homomorphic ElGamal
* **Two Party Protocols:**
  * DH key exchange
  * Coin Flip

### Security  
The library was audited by [Kudelski security](https://www.kudelskisecurity.com/) on Feb19. The report can be found [here](https://github.com/KZen-networks/curv/tree/master/audit). No critical issue was found and all issues found were fixed.

The code was reviewed independently by few other cryptographers. Special thanks goes to [Claudio Orlandi](http://cs.au.dk/~orlandi/) from Aarhus University. 

In general security of the library is strongly dependent on the security of the low level libraries used. We chose only libraries that are used as part of other big projects and went through heavy audit/review. 

The library is not immune to side channel attacks but considerable effort was given to try and catch as many such attacks as possible (see audit report). 

### Build
By default `cargo build` will build the library only for `BigInt`. To add opertions for one of the elliptic curves 
a feature must be specified:
- `cargo build --features=ec_secp256k1` for secp256k1
- `cargo build --features=ec_ed25519` for ed25519
- `cargo build --features=ec_jubjub` for jubjub
- `cargo build --features=ec_ristretto` for ristretto

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
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

### Contact
For any questions, feel free to [email us](mailto:github@kzencorp.com).
