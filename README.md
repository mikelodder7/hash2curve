# Hash to curve algorithms for Rust 

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][ci-build-image]][build-link]
[![dependency status][deps-image]][deps-link]
[![Apache 2.0 Licensed][license-image]][license-link]
![Maintenance Status: Experimental][maintenance-image]
[![Safety Dance][safety-image]][safety-link]

This repository implements various algorithms that can be used to encode or hash arbitrary input to a point on an
elliptic curve or a set of recommended algorithms for a range of curve types.

## Status

This crate is **experimental** and may have bugs/memory safety issues.
*USE AT YOUR OWN RISK!*

Below is an outline of the of the suites supported by this crate:

- [ ] Suites for NIST P-256
- [ ] Suites for NIST P-384
- [ ] Suites for NIST P-521
- [ ] Suites for Curve25519 and Ed25519
- [ ] Suites for Curve448 and Ed448
- [ ] Suites for Secp256k1
- [ ] Suites for BLS12-381
    - [ ] BLS12-381 G1
    - [ ] BLS12-381 G2
    
## Examples on using the code

```rust
```
    
## Tests
The tests can be execute by running: `cargo test`
    

# Author

Michael Lodder

# License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.

# References

- [Current IETF Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1)
- [Test Vectors](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve)
- [BLS-12-381 Constant Time Reference](https://eprint.iacr.org/2019/403.pdf)
- [Talk given by Wahby & Boneh](https://wahby.org/bls-hash-ecc19-talk.pdf)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/hash2curve.svg
[crate-link]: https://crates.io/crates/hash2curve
[docs-image]: https://docs.rs/hash2curve/badge.svg
[docs-link]: https://docs.rs/hash2curve/
[ci-build-image]: https://github.com/mikelodder7/hash2curve/workflows/CI/badge.svg?branch=master&event=push
[build-link]: https://github.com/mikelodder7/hash2curve/actions
[safety-image]: https://img.shields.io/badge/unsafe-forbidden-success.svg
[safety-link]: https://github.com/rust-secure-code/safety-dance/
[deps-image]: https://deps.rs/repo/github/mikelodder7/hash2curve/status.svg
[deps-link]: https://deps.rs/repo/github/mikelodder7/hash2curve 
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[license-link]: https://github.com/mikelodder7/hash2curve/blob/master/LICENSE-APACHE
[maintenance-image]: https://img.shields.io/badge/maintenance-experimental-blue.svg