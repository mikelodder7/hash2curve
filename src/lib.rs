//! This implements the hash to curve as described in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//!
//! The idea is to offer concrete methods for hashing arbitrary input to a point on an
//! elliptic curve used in cryptography.

#[cfg(feature = "bls")]
pub mod bls381g1;

