# Changelog

## v0.8.0-rc4
* Implement Try and Increment when converting hash to scalar [#128] \
  Improves performance and security of conversion 🔥
* Get rid of deprecated `rust-crypto` dependency [#137]
  * Changed the crate providing merkle trees support: `merkle-sha3 v0.1` → `merkle-cbt v0.3`
  * Merkle trees API has been slightly changed
  * Merkle trees are generic over hash function (it used to work with keccak256 only)
  * Merkle proofs built by previous versions of `curv` are incompatible with latest `curv`

[#128]: https://github.com/ZenGo-X/curv/pull/128
[#137]: https://github.com/ZenGo-X/curv/pull/137

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
