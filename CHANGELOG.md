# Changelog

## v0.9.0
* Change `Polynomial::degree` to return a special enum `PolynomialDegree` [#147] \
  `PolynomialDegree` correctly represent a degree of polynomial that can be either infinite (for polynomial `f(x) = 0`)
  or finite (for all other sorts of polynomials)


[#147]: https://github.com/ZenGo-X/curv/pull/148

## v0.8.3
* Add `generate_random_point` function from `centipede`, `bulletproof` crates [#148] \
  It takes uniformly distributed bytes and produces secp256k1 point with unknown logarithm. 
  Subject to change in near future.

[#148]: https://github.com/ZenGo-X/curv/pull/148

## v0.8.2
* Bugfix for BigInt deserialization via serde_json [#145]

[#145]: https://github.com/ZenGo-X/curv/pull/145

## v0.8.1
* Bugfix for points/scalars deserialization via serde_json [#143]

[#143]: https://github.com/ZenGo-X/curv/pull/143

## v0.8.0
* Implement Try and Increment when converting hash to scalar [#128] \
  Improves performance and security of conversion 🔥
* Get rid of deprecated `rust-crypto` dependency [#137]
  * Changed the crate providing merkle trees support: `merkle-sha3 v0.1` → `merkle-cbt v0.3`
  * Merkle trees API has been slightly changed
  * Merkle trees are generic over hash function (it used to work with keccak256 only)
  * Merkle proofs built by previous versions of `curv` are incompatible with latest `curv`
* Make the commitments generic over the hash function [#129] \
  Allows the user to choose their own hash function when using our hash and related commitments
* Unify and optimise bigint serialization [#139]
  * Bigints are serialized as bytes (instead of converting to hex/decimal format), that should save communication size 
    (depends on serialization backend)
  * Different backends serialize bigints in the same way, ie. number serialized via `rust-gmp` backend will be properly
    deserialized via `num-bigint` backend and vice-versa
  * Compatibility notes: bigints serialization format is changed, so numbers serialized with older curv are not compatible
    with the newest version

[#128]: https://github.com/ZenGo-X/curv/pull/128
[#129]: https://github.com/ZenGo-X/curv/pull/129
[#137]: https://github.com/ZenGo-X/curv/pull/137
[#139]: https://github.com/ZenGo-X/curv/pull/139

## v0.8.0-rc3
* Fix point subtraction. Bug was introduced in `v0.8.0-rc1`. [#127]
* Add `Polynomial::lagrange_basis` function [#130]
* Katex <> Docs integration [#131] \
  Allows using KaTeX in documentation comments. Math formulas will be properly rendered on docs.rs.
* LDEI proof minor improvements [#133] \
  Adds missing implementations of Clone and serialization traits.
* Update `hmac`, `digest`, `sha2`,`sha3` dependencies [#134] \
  `hmac`: `v0.7.1` → `v0.11` \
  `digest`: `v0.8.1` → `v0.9` \
  `sha2`: `v0.8.0` → `v0.9` \
  `sha3`: `v0.8.2` → `v0.9`

[#127]: https://github.com/ZenGo-X/curv/pull/127
[#130]: https://github.com/ZenGo-X/curv/pull/130
[#131]: https://github.com/ZenGo-X/curv/pull/131
[#133]: https://github.com/ZenGo-X/curv/pull/133
[#134]: https://github.com/ZenGo-X/curv/pull/134

## v0.8.0-rc2
* Remove dependency on `ring_algorithm` crate [#125], [#124]

[#125]: https://github.com/ZenGo-X/curv/pull/125
[#124]: https://github.com/ZenGo-X/curv/issues/124

## v0.8.0-rc1
* Elliptic curve API has been significantly changed [#120]
  
  In particular: ECPoint, ECScalar traits were redesigned. They remain,
  but are not supposed to be used directly anymore. In replacement,
  we introduce structures Point, Scalar representing elliptic point and
  scalar. See curv::elliptic::curves module-level documentation to learn 
  more.
* Add low degree exponent interpolation proof [#119]

[#119]: https://github.com/ZenGo-X/curv/pull/119
[#120]: https://github.com/ZenGo-X/curv/pull/120
