#![deny(
// warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSeparationTag {
    /// Fixed protocol identification string.
    /// This identification string should be unique to the protocol.
    protocol_id: String,
    /// Protocol version number, can be any format 1, 01, 1.0, 2.0.2
    protocol_version: String,
    /// For protocols that define multiple ciphersuites, each
    /// ciphersuite's tag MUST be different.  For this purpose, it is
    /// RECOMMENDED to include a ciphersuite identifier in each tag.
    ciphersuite_id: String,
    /// For protocols that use multiple encodings, either to the same
    /// curve or to different curves, each encoding MUST use a different
    /// tag.  For this purpose, it is RECOMMENDED to include the
    /// encoding's Suite ID (Section 8) in the domain separation tag.
    /// For independent encodings based on the same suite, each tag
    /// should also include a distinct identifier.
    encoding_id: String,
}

impl DomainSeparationTag {
    /// Convenience function for creating a domain separation tag
    pub fn new(
        protocol_id: &str,
        protocol_version: Option<&str>,
        ciphersuite_id: Option<&str>,
        encoding_id: Option<&str>,
    ) -> Result<Self, HashingError> {
        Self::check_min_length(protocol_id)?;
        let dms = Self {
            protocol_id: protocol_id.to_string(),
            protocol_version: protocol_version.unwrap_or("").to_string(),
            ciphersuite_id: ciphersuite_id.unwrap_or("").to_string(),
            encoding_id: encoding_id.unwrap_or("").to_string(),
        };
        Ok(dms)
    }

    /// Convert the tag to bytes. All fields cannot be longer than 255 bytes in length
    /// If a domain separation tag longer than 255 bytes must be used (e.g., because of requirements
    /// imposed by an invoking protocol), this computes the
    /// H("H2C-OVERSIZE-DST-" || protocol_id || procotol_version || ciphersuite_id || encoding_id)
    /// `D` must be a cryptographically secure hash function like SHA256, SHA3-256, or BLAKE2.
    pub fn to_bytes<D: Digest<OutputSize = U32>>(&self) -> Result<Vec<u8>, HashingError> {
        Self::check_min_length(&self.protocol_id)?;

        let output = self.to_slice();

        if output.len() > MAX_DMS_SIZE {
            let mut hasher = D::new();
            hasher.input(b"H2C-OVERSIZE-DST-");
            hasher.input(output.as_slice());
            Ok(hasher.result().to_vec())
        } else {
            Ok(output)
        }
    }

    /// Check that there is at least `MIN_DMS_PROTOCOL_ID_SIZE` bytes in the domain separation tag.
    fn check_min_length(protocol_id: &str) -> Result<(), HashingError> {
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

    /// Check that there is at most `MAX_DMS_SIZE` bytes
    fn check_max_length<I: AsRef<[u8]>>(output: I) -> Result<(), HashingError> {
        if output.as_ref().len() > MAX_DMS_SIZE {
            return Err(HashingError::from_msg(
                HashingErrorKind::InvalidDomainSeparationTag,
                format!(
                    "Domain separation tag cannot be longer than {}",
                    MAX_DMS_SIZE
                ),
            ));
        }
        Ok(())
    }

    /// Convert all the fields into a byte array
    fn to_slice(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(self.protocol_id.as_bytes());
        output.extend_from_slice(self.protocol_version.as_bytes());
        output.extend_from_slice(self.ciphersuite_id.as_bytes());
        output.extend_from_slice(self.encoding_id.as_bytes());
        output
    }
}

/// The `HashToCurve` trait specifies an interface common for mapping to curve functions.
pub trait HashToCurve {
    /// The return type by the underlying hash to curve implementation
    type Output;
    /// Nonuniform encoding.  This function encodes byte
    /// strings to points in G.  The distribution of the output is not
    /// uniformly random in G.
    fn encode_to_curve<I: AsRef<[u8]>>(&self, data: I) -> Result<Self::Output, HashingError>;

    /// Random oracle encoding (hash_to_curve).  This function encodes
    /// byte strings to points in G.  This function is suitable for
    /// applications requiring a random oracle returning points in G,
    /// provided that map_to_curve is "well distributed".
    fn hash_to_curve<I: AsRef<[u8]>>(&self, data: I) -> Result<Self::Output, HashingError>;
}

/// The maximum number of bytes that can be requested for an expand operation
const MAX_EXPAND_MESSAGE_REQUEST: usize = 255;

/// Implements the `expand_message_xof` as described in section 5.3.2 at
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
/// computes hash function `D` from `msg` and the tag
pub(crate) fn expand_message_xof<M, X, D, T>(
    msg: M,
    dst: &DomainSeparationTag,
) -> Result<GenericArray<u8, T>, HashingError>
where
    M: AsRef<[u8]>,
    X: ExtendableOutput + Input + Reset + Default,
    D: Digest<OutputSize = U32>,
    T: ArrayLength<u8>,
{
    if T::to_usize() == 0 {
        return Err(HashingError::from_msg(
            HashingErrorKind::InvalidXmdRequestLength,
            "The requested output cannot be 0".to_string(),
        ));
    }

    let mut dst_prime = dst.to_bytes::<D>()?;
    dst_prime.insert(0, dst_prime.len() as u8); //I2OSP(len(DST), 1) || DST
    let mut hasher = X::default();
    hasher.input(msg.as_ref());
    hasher.input(T::to_u16().to_be_bytes());             //I2OSP(len_in_bytes, 2)
    hasher.input(dst_prime.as_slice());
    let mut result = vec![0u8; T::to_usize()];
    hasher.xof_result().read(result.as_mut_slice());
    Ok(GenericArray::from_iter(result.into_iter()))
}

/// Implements the `expand_message_xmd` as described in section 5.3.1 at
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
/// computes hash function `D` from `msg` and the tag
pub(crate) fn expand_message_xmd<M, D, T>(
    msg: M,
    dst: &DomainSeparationTag,
) -> Result<GenericArray<u8, T>, HashingError>
where
    M: AsRef<[u8]>,
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
    let mut dst_prime = dst.to_bytes::<D>()?;
    dst_prime.insert(0, dst_prime.len() as u8); //I2OSP(len(DST), 1) || DST
    let mut hasher = D::new();
    hasher.input(vec![0u8; D::BlockSize::to_usize()]);   //z_pad = I2OSP(0, r_in_bytes)
    hasher.input(msg.as_ref());
    hasher.input(T::to_u16().to_be_bytes());             //l_i_b_str = I2OSP(len_in_bytes, 2)
    hasher.input([0u8]); //I2OSP(0, 1)
    hasher.input(dst_prime.as_slice());
    let b_0 = hasher.result_reset();        //b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    hasher.input(b_0);
    hasher.input([1u8]); //I2OSP(1, 1)
    hasher.input(dst_prime.as_slice());
    let mut b_i = hasher.result_reset();    //b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut random_bytes = Vec::new();
    random_bytes.extend_from_slice(b_i.as_slice());
    // Its tempting to terminate early because we only need to loop until enough
    // bytes are in `random_bytes`. However, this wouldn't be CT
    for i in 1..ell {
        hasher.input(vxor(b_0.as_slice(), b_i.as_slice()).as_slice());
        hasher.input([(i + 1) as u8]);
        hasher.input(dst_prime.as_slice());
        b_i = hasher.result_reset();                            //b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        random_bytes.extend_from_slice(b_i.as_slice());
    }
    Ok(GenericArray::from_iter(random_bytes.into_iter().take(T::to_usize())))
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

mod isogeny;

/// Hashing for BLS12-381 to G1
#[cfg(feature = "bls")]
pub mod bls381g1;

/// Errors generated by this crate
pub mod error;
