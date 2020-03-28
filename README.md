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
    - [x] BLS12-381 G1
    - [ ] BLS12-381 G2
    
## Examples on using the code
To get started, you must define a `DomainSeparationTag` for your protocol use. 
According to section 3.1 in [Current IETF Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1),
domain separation tags must include a protocol id, and some other options like versioning, ciphersuites, and encoding
names. 

```rust 
use hash2curve::DomainSeparationTag

let dst = DomainSeparationTag::new(b"MySuperAwesomeProtocol", None, None, None).unwrap();
```

`DomainSeparationTag` requires at least one 1 character otherwise `new` will throw an Err. This tag
will then be used for creating a hash to curve struct. A good `DomainSeparationTag` according to the [Current IETF Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1)
is protocol id = "BLS12381G1_XMD:SHA-256_SSWU_RO_" which translates to mean hash on curve BLS12-381 to a point on G1 using the expand_message_xmd,
the SHA-256 hash algorithm, the Simple SWU isogeny map, with a random oracle output (the output is indistinguishable from a random string).
A protocol version might be 1.0, the ciphersuites could be "signatures", and "encoding" could be "base64". Only the protocol id is required. 

Hashers are defined to create points on specific curves. All hashers define at least `HashToCurveXmd` or `HashToCurveXof`.

`HashToCurveXmd` is designed to use cryptographically secure hash functions like SHA-2 or SHA-3. 
`HashToCurveXof` is designed to use extensible output functions like SHAKE-128.
Use the appropriate hasher struct for the curve used in your protocol.

Here is an example of creating BLS12-381 point using the hash to curve based on [Apache Milagro](https://github.com/miracl/amcl/tree/master/version3/rust)

```rust
use hash2curve::{DomainSeparationTag, HashToCurveXmd, bls381g1::Bls12381G1Sswu};

let dst = DomainSeparationTag::new(b"BLS12381G1_XMD:SHA-256_SSWU_RO_", Some(b"0.1.0"), None, None).unwrap();

let hasher = Bls12381G1Sswu::new(dst);

let msg = b"A message to sign";

// sign the message assuming signatures are in G1 like tiny BLS
let point_on_g1 = hasher.hash_to_curve_xmd::<sha2::Sha256>(msg);
let signature = point_on_g1.mul(&private_key);

// Or extract the bytes or save as hexstring
let point_on_g1 = hasher.hash_to_curve_xmd::<sha2::Sha256>(msg);
```
    
## Tests
The tests can be execute by running: `cargo test`. However, since curves are very specific, no curve is enabled by default.
Instead, the appropriate hasher struct can included using the following:

### Current Features

- bls: `cargo test --features=bls`

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
- [Riad Wahby C Implementation](https://github.com/kwantam/bls12-381_hash)

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