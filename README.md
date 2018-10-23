[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)


=====================================

This project implements basic cryptographic primitives over elliptic curves. The API code is Rust native while the used elliptic curve libraries can be binding to other languages. 

__Supported Curves__: 

* _secp256k1_ [https://github.com/rust-bitcoin/rust-secp256k1]
* _curve25519_ (Ristretto) [https://github.com/dalek-cryptography/curve25519-dalek]

__Supported Primitives__: 

* **Hash Functions**: SHA256, SHA512, HMAC-SHA512, Merkle-Tree
* **Commitment Schemes**: Hash based, Pedersen
* **Secret Sharing**: Feldman VSS
* **Sigma Protocols:** 
  * Proof of knowledge of EC-DLog
  * Proof of correct Pedersen
  * Proof of correct Homomorphic ElGamal
* **Two Party Protocols:**
  * DH key exchange
  * Coin Flip
 

License
-------
Cryptography utilities is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.


Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).
