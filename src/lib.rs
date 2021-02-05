#![deny(
    warnings,
    missing_docs,
    unsafe_code,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
//! This implements the hash to curve as described in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//!
//! The idea is to offer concrete methods for hashing arbitrary input to a point on an
//! elliptic curve used in cryptography.
//!
//! As much as possible, the interfaces, structs, and traits have been modeled after
//! the RustCrypto `digest` crate at <https://docs.rs/digest/>
//!
//! These methods do not cover serialization or deserialization according to
//! <http://www.secg.org/sec1-v2.pdf>

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// A facade around all the types from `std`, `core`, and `alloc`
/// crates. Avoids elaborate import wrangling having to happen in every module
mod lib {
    mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }

    pub use self::core::fmt::{self, Debug, Display, Result as FmtResult};
    pub use self::core::marker::{self, PhantomData};
    pub use self::core::option::{self, Option};
    pub use self::core::result::{self, Result};
    pub use self::core::{u32, u64, usize};

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    pub use alloc::vec::Vec;
    #[cfg(feature = "std")]
    pub use std::vec::Vec;
}

mod error;
/// The error types of this crate
pub use error::*;

mod from_ro;
/// From random oracle traits
pub use from_ro::*;

mod expand_msg;
/// expand_msg traits and methods
pub use expand_msg::*;

mod hash_to_field;
/// hash to field traits and methods
pub use hash_to_field::*;

/// Random oracle map to curve
pub trait HashToCurve<X>
where
    X: ExpandMsg,
{
    /// Random oracle
    fn hash_to_curve<M: AsRef<[u8]>, D: AsRef<[u8]>>(msg: M, dst: D) -> Self;
}

/// Injective oracle map to curve
pub trait EncodeToCurve<X>
where
    X: ExpandMsg,
{
    /// Injective encoding
    fn encode_to_curve<M: AsRef<[u8]>, D: AsRef<[u8]>>(msg: M, dst: D) -> Self;
}
