# Changelog

## v0.8.0-rc3
* Fix point subtraction. Bug was introduced in `v0.8.0-rc1`. [#127]

[#127]: https://github.com/ZenGo-X/curv/pull/127

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
