[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Curv
=====================================

This project implements basic cryptographic primitives over elliptic curves. The API code is Rust native while the used elliptic curve libraries can be binding to other languages. 

__Supported Curves__: 

* [_secp256k1_](https://github.com/rust-bitcoin/rust-secp256k1)
* [_ed25519_ ](https://github.com/typed-io/cryptoxide/blob/master/src/curve25519.rs)
* [_ristretto_](https://github.com/dalek-cryptography/curve25519-dalek)

__Supported Primitives__: 

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
 
### Adding An Elliptic Curve
To add support of this primitives to new elliptic curve the following interfaces (trait) needs to be fulfilled for field element and group element: 
```
pub trait ECScalar<SK> {
    fn new_random() -> Self;
    fn zero() -> Self;
    fn get_element(&self) -> SK;
    fn set_element(&mut self, element: SK);
    fn from(n: &BigInt) -> Self;
    fn to_big_int(&self) -> BigInt;
    fn q() -> BigInt;
    fn add(&self, other: &SK) -> Self;
    fn mul(&self, other: &SK) -> Self;
    fn sub(&self, other: &SK) -> Self;
    fn invert(&self) -> Self;
}


pub trait ECPoint<PK, SK>
where
    Self: Sized,
{
    fn generator() -> Self;
    fn get_element(&self) -> PK;
    fn x_coor(&self) -> BigInt;
    fn y_coor(&self) -> BigInt;
    fn bytes_compressed_to_big_int(&self) -> BigInt;
    fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorKey>;
    fn pk_to_key_slice(&self) -> Vec<u8>;
    fn scalar_mul(&self, fe: &SK) -> Self;
    fn add_point(&self, other: &PK) -> Self;
    fn sub_point(&self, other: &PK) -> Self;
    fn from_coor(x: &BigInt, y: &BigInt) -> Self;
}
```
License
-------
Cryptography utilities is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.


Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).
