#![deny(
// warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
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

use crate::error::{HashingError, HashingErrorKind};
use digest::{
    generic_array::{
        typenum::{marker_traits::Unsigned, U32},
        ArrayLength, GenericArray,
    },
    BlockInput, Digest, ExtendableOutput, Input, Reset, XofReader,
};
use std::iter::FromIterator;

/// The minimum length for a protocol id.
pub const MIN_DMS_PROTOCOL_ID_SIZE: usize = 1;
/// The longest the domain separation tag can be in bytes
pub const MAX_DMS_SIZE: usize = 255;

/// Represents a domain separation tag suitable for use in
/// `hash_to_curve` or `encode_to_curve` functions as describe in section 3.1
/// in <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
///
/// As an example, consider a fictional protocol named Quux that defines
/// several different ciphersuites.  A reasonable choice of tag is "QUUX-
/// V<xx>-CS<yy>", where <xx> and <yy> are two-digit numbers indicating
/// the version and ciphersuite, respectively.
///
/// As another example, consider a fictional protocol named Baz that
/// requires two independent random oracles, where one oracle outputs
/// points on the curve E1 and the other outputs points on the curve E2.
/// Reasonable choices of tags for the E1 and E2 oracles are "BAZ-V<xx>-
/// CS<yy>-E1" and "BAZ-V<xx>-CS<yy>-E2", respectively, where <xx> and
/// <yy> are as described above.
///
/// ```
/// use hash2curve::DomainSeparationTag;
///
/// let dst = DomainSeparationTag::new(b"MySuperAwesomeProtocol", None, None, None);
///
/// assert!(dst.is_ok());
///
/// let dst = DomainSeparationTag::new(b"", None, None, None);
///
/// assert!(dst.is_err());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSeparationTag {
    /// Fixed protocol identification string.
    /// This identification string should be unique to the protocol.
    protocol_id: Vec<u8>,
    /// Protocol version number, can be any format 1, 01, 1.0, 2.0.2
    protocol_version: Vec<u8>,
    /// For protocols that define multiple ciphersuites, each
    /// ciphersuite's tag MUST be different.  For this purpose, it is
    /// RECOMMENDED to include a ciphersuite identifier in each tag.
    ciphersuite_id: Vec<u8>,
    /// For protocols that use multiple encodings, either to the same
    /// curve or to different curves, each encoding MUST use a different
    /// tag.  For this purpose, it is RECOMMENDED to include the
    /// encoding's Suite ID (Section 8) in the domain separation tag.
    /// For independent encodings based on the same suite, each tag
    /// should also include a distinct identifier.
    encoding_id: Vec<u8>,
}

impl DomainSeparationTag {
    /// Convenience function for creating a domain separation tag
    pub fn new(
        protocol_id: &[u8],
        protocol_version: Option<&[u8]>,
        ciphersuite_id: Option<&[u8]>,
        encoding_id: Option<&[u8]>,
    ) -> Result<Self, HashingError> {
        Self::check_min_length(protocol_id)?;
        let dms = Self {
            protocol_id: protocol_id.to_vec(),
            protocol_version: protocol_version.map_or_else(|| Vec::new(), |p| p.to_vec()),
            ciphersuite_id: ciphersuite_id.map_or_else(|| Vec::new(), |c| c.to_vec()),
            encoding_id: encoding_id.map_or_else(|| Vec::new(), |e| e.to_vec()),
        };
        Ok(dms)
    }

    /// Convert the tag to bytes. All fields cannot be longer than 255 bytes in length
    /// If a domain separation tag longer than 255 bytes must be used (e.g., because of requirements
    /// imposed by an invoking protocol), this computes the
    /// H("H2C-OVERSIZE-DST-" || protocol_id || procotol_version || ciphersuite_id || encoding_id)
    /// `D` must be a cryptographically secure hash function like SHA256, SHA3-256, or BLAKE2.
    pub fn to_bytes(&self) -> Vec<u8> {
        let output = self.to_slice();

        if output.len() > MAX_DMS_SIZE {
            let mut data = b"H2C-OVERSIZE-DST-".to_vec();
            data.extend_from_slice(output.as_slice());
            sha2::Sha256::digest(data.as_slice()).to_vec()
        } else {
            output
        }
    }

    /// Check that there is at least `MIN_DMS_PROTOCOL_ID_SIZE` bytes in the domain separation tag.
    fn check_min_length(protocol_id: &[u8]) -> Result<(), HashingError> {
        if protocol_id.len() < MIN_DMS_PROTOCOL_ID_SIZE {
            return Err(HashingError::from_msg(
                HashingErrorKind::InvalidDomainSeparationTag,
                format!(
                    "Must specify a protocol id of at least {} characters",
                    MIN_DMS_PROTOCOL_ID_SIZE
                ),
            ));
        }
        Ok(())
    }

    /// Convert all the fields into a byte array
    fn to_slice(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(self.protocol_id.as_slice());
        output.extend_from_slice(self.protocol_version.as_slice());
        output.extend_from_slice(self.ciphersuite_id.as_slice());
        output.extend_from_slice(self.encoding_id.as_slice());
        output
    }
}

/// The `HashToCurveXmd` trait specifies an interface common for mapping to curve functions using XMD to expand the message.
pub trait HashToCurveXmd {
    /// The return type by the underlying hash to curve implementation
    type Output;
    /// Nonuniform encoding.  This function encodes byte
    /// strings to points in G.  The distribution of the output is not
    /// uniformly random in G.
    fn encode_to_curve_xmd<D: BlockInput + Digest<OutputSize = U32>>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError>;

    /// Random oracle encoding (hash_to_curve).  This function encodes
    /// byte strings to points in G.  This function is suitable for
    /// applications requiring a random oracle returning points in G,
    /// provided that map_to_curve is "well distributed".
    fn hash_to_curve_xmd<D: BlockInput + Digest<OutputSize = U32>>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError>;
}

/// The `HashToCurveXof` trait specifies an interface common for mapping to curve functions using XMD to expand the message.
pub trait HashToCurveXof {
    /// The return type by the underlying hash to curve implementation
    type Output;

    /// Nonuniform encoding.  This function encodes byte
    /// strings to points in G.  The distribution of the output is not
    /// uniformly random in G.
    fn encode_to_curve_xof<X: ExtendableOutput + Input + Reset + Default>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError>;

    /// Random oracle encoding (hash_to_curve).  This function encodes
    /// byte strings to points in G.  This function is suitable for
    /// applications requiring a random oracle returning points in G,
    /// provided that map_to_curve is "well distributed".
    fn hash_to_curve_xof<X: ExtendableOutput + Input + Reset + Default>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError>;
}

/// The maximum number of bytes that can be requested for an expand operation
const MAX_EXPAND_MESSAGE_REQUEST: usize = 255;

/// Implements the `expand_message_xof` as described in section 5.3.2 at
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
/// computes hash function `D` from `msg` and the tag
pub(crate) fn expand_message_xof<X, T>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<GenericArray<u8, T>, HashingError>
where
    X: ExtendableOutput + Input + Reset + Default,
    T: ArrayLength<u8>,
{
    if T::to_usize() == 0 {
        return Err(HashingError::from_msg(
            HashingErrorKind::InvalidXmdRequestLength,
            "The requested output cannot be 0".to_string(),
        ));
    }

    let mut dst_prime = dst.to_bytes();
    dst_prime.insert(0, dst_prime.len() as u8); //I2OSP(len(DST), 1) || DST
    let mut hasher = X::default();
    hasher.input(msg.as_ref());
    hasher.input(T::to_u16().to_be_bytes()); //I2OSP(len_in_bytes, 2)
    hasher.input(dst_prime.as_slice());
    let mut result = vec![0u8; T::to_usize()];
    hasher.xof_result().read(result.as_mut_slice());
    Ok(GenericArray::from_iter(result.into_iter()))
}

/// Implements the `expand_message_xmd` as described in section 5.3.1 at
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
/// computes hash function `D` from `msg` and the tag
pub(crate) fn expand_message_xmd<D, T>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<GenericArray<u8, T>, HashingError>
where
    D: BlockInput + Digest<OutputSize = U32>,
    T: ArrayLength<u8>,
{
    if T::to_usize() == 0 {
        return Err(HashingError::from_msg(
            HashingErrorKind::InvalidXmdRequestLength,
            "The requested output cannot be 0".to_string(),
        ));
    }
    let ell = f64::ceil(T::to_usize() as f64 / D::OutputSize::to_usize() as f64) as usize;
    if ell > MAX_EXPAND_MESSAGE_REQUEST {
        return Err(HashingError::from_msg(
            HashingErrorKind::InvalidXmdRequestLength,
            format!(
                "The requested output cannot be longer than {}",
                MAX_EXPAND_MESSAGE_REQUEST
            ),
        ));
    }
    let mut dst_prime = dst.to_bytes();
    dst_prime.insert(0, dst_prime.len() as u8); //I2OSP(len(DST), 1) || DST
    let mut hasher = D::new();
    hasher.input(vec![0u8; D::BlockSize::to_usize()]); //z_pad = I2OSP(0, r_in_bytes)
    hasher.input(msg);
    hasher.input(T::to_u16().to_be_bytes()); //l_i_b_str = I2OSP(len_in_bytes, 2)
    hasher.input([0u8]); //I2OSP(0, 1)
    hasher.input(dst_prime.as_slice());
    let b_0 = hasher.result_reset(); //b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    hasher.input(b_0);
    hasher.input([1u8]); //I2OSP(1, 1)
    hasher.input(dst_prime.as_slice());
    let mut b_i = hasher.result_reset(); //b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut random_bytes = Vec::new();
    random_bytes.extend_from_slice(b_i.as_slice());
    // Its tempting to terminate early because we only need to loop until enough
    // bytes are in `random_bytes`. However, this wouldn't be CT
    for i in 1..ell {
        hasher.input(vxor(b_0.as_slice(), b_i.as_slice()).as_slice());
        hasher.input([(i + 1) as u8]);
        hasher.input(dst_prime.as_slice());
        b_i = hasher.result_reset(); //b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        random_bytes.extend_from_slice(b_i.as_slice());
    }
    Ok(GenericArray::from_iter(
        random_bytes.into_iter().take(T::to_usize()),
    ))
}

/// Internal function returns the bitwise XOR of the two strings.
fn vxor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    debug_assert!(b1.len() == b2.len());
    let mut result = Vec::with_capacity(b1.len());
    for i in 0..b1.len() {
        result.push(b1[i] ^ b2[i]);
    }
    result
}

/// Convenience export module
pub mod prelude {
    pub use super::{HashToCurveXmd, HashToCurveXof, DomainSeparationTag};
    pub use super::error::{HashingError, HashingErrorKind};
    #[cfg(feature = "bls")]
    pub use super::bls381g1::{Bls12381G1Sswu, G1};
}

mod isogeny;

/// Hashing for BLS12-381 to G1
#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
pub mod bls381g1;

#[cfg(feature = "bls")]
#[cfg_attr(docrs, doc(cfg(feature = "bls")))]
pub mod bls381g2;

/// Errors generated by this crate
pub mod error;
