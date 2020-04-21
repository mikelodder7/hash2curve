//! Implements hash to curve as described in Section 8.7.1 of
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//! and Section 5 of
//!  <https://eprint.iacr.org/2019/403.pdf>

use crate::constants::bls381g1::*;
use crate::error::HashingError;
use crate::isogeny::bls381g1::*;
use crate::{expand_message_xmd, expand_message_xof, DomainSeparationTag};
use crate::{HashToCurveXmd, HashToCurveXof};
use amcl::arch::Chunk;
use amcl::bls381::{big::BIG, dbig::DBIG, ecp::ECP, rom};
use digest::generic_array::GenericArray;
use digest::{
    generic_array::typenum::{marker_traits::Unsigned, U128, U32, U48, U64, U96},
    BlockInput, Digest, ExtendableOutput, Input, Reset,
};
use failure::_core::fmt::Debug;
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use subtle::ConstantTimeEq;

/// To compute a `L` use the following formula
/// L = ceil(ceil(log2(p) + k) / 8). For example, in our case log2(p) = 381, k = 128
/// L = 64
type L = U64;
type TwoL = U128;

/// BLS12381G1_XMD:SHA-256_SSWU provides both
/// Random Oracle (RO)
/// Nonuniform (NU)
pub struct Bls12381G1Sswu {
    dst: DomainSeparationTag,
}

impl Bls12381G1Sswu {
    /// Create a new implementation with the default
    pub fn new(dst: DomainSeparationTag) -> Self {
        Self { dst }
    }
}

impl From<DomainSeparationTag> for Bls12381G1Sswu {
    fn from(dst: DomainSeparationTag) -> Self {
        Self { dst }
    }
}

impl HashToCurveXmd for Bls12381G1Sswu {
    type Output = G1;

    fn encode_to_curve_xmd<D: BlockInput + Digest<OutputSize = U32>>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError> {
        let u = hash_to_field_xmd_nu::<D>(data, &self.dst)?;
        Ok(encode_to_curve(u).into())
    }

    fn hash_to_curve_xmd<D: BlockInput + Digest<OutputSize = U32>>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError> {
        let (u0, u1) = hash_to_field_xmd_ro::<D>(data, &self.dst)?;
        Ok(hash_to_curve(u0, u1).into())
    }
}

impl HashToCurveXof for Bls12381G1Sswu {
    type Output = G1;

    fn encode_to_curve_xof<X: ExtendableOutput + Input + Reset + Default>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError> {
        let u = hash_to_field_xof_nu::<X>(data, &self.dst)?;
        Ok(encode_to_curve(u).into())
    }

    fn hash_to_curve_xof<X: ExtendableOutput + Input + Reset + Default>(
        &self,
        data: &[u8],
    ) -> Result<Self::Output, HashingError> {
        let (u0, u1) = hash_to_field_xof_ro::<X>(data, &self.dst)?;
        Ok(hash_to_curve(u0, u1).into())
    }
}

/// Represents a point on G1
#[derive(Copy, Clone)]
pub struct G1(pub ECP);

impl G1 {
    /// The bytes in G1 compressed form
    pub const COMPRESSED_BYTES: usize = rom::MODBYTES;
    /// The bytes in G1 uncompressed form
    pub const UNCOMPRESSED_BYTES: usize = 2 * rom::MODBYTES;
    const ECP_COMPRESSED: usize = Self::COMPRESSED_BYTES + 1;
    const ECP_UNCOMPRESSED: usize = Self::UNCOMPRESSED_BYTES + 1;
    const COMPRESSED_HEX_LENGTH: usize = Self::UNCOMPRESSED_BYTES;
    const UNCOMPRESSED_HEX_LENGTH: usize = Self::UNCOMPRESSED_BYTES * 2;

    /// Serialize the point to compressed bytes in big endian form
    /// Only the x-coordinate
    ///
    /// NOTE: Must use `GenericArray` due to rust error
    /// error[E0277]: arrays only have std trait implementations for lengths 0..=32
    /// The caller can use section 4.3 in https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html
    /// to reconstruct Y if needed
    pub fn to_bytes(&self) -> [u8; Self::COMPRESSED_BYTES] {
        let mut bytes = [0u8; Self::ECP_COMPRESSED];
        let mut temp = ECP::new();
        temp.copy(&self.0);
        temp.tobytes(bytes.as_mut(), true);
        // GenericArray::clone_from_slice(&bytes[1..])
        let mut output = [0u8; Self::COMPRESSED_BYTES];
        output.copy_from_slice(&bytes[1..]);
        // Store the value of y as the MSB
        output[0] |= (bytes[0] & 1) << 7;
        output
    }

    /// Serialize the point to uncompressed bytes in big endian form
    /// The x-coordinate followed by the y-coordinate
    /// NOTE: Must use `GenericArray` due to rust error
    /// error[E0277]: arrays only have std trait implementations for lengths 0..=32
    pub fn to_bytes_uncompressed(&self) -> [u8; Self::UNCOMPRESSED_BYTES] {
        let mut bytes = [0u8; Self::ECP_UNCOMPRESSED];
        let mut temp = ECP::new();
        temp.copy(&self.0);
        temp.tobytes(bytes.as_mut(), false);
        // GenericArray::clone_from_slice(&bytes[1..])
        let mut output = [0u8; Self::UNCOMPRESSED_BYTES];
        output.copy_from_slice(&bytes[1..]);
        output
    }

    /// Serialize the point to compressed lower hex string
    /// Only the x-coordinate
    pub fn encode_to_hex(&self) -> String {
        String::from_utf8(subtle_encoding::hex::encode(&self.to_bytes()[..])).unwrap()
    }

    /// Serialize the point to uncompressed lower hex string
    /// The x-coordinate followed by the y-coordinate
    pub fn encode_to_hex_uncompressed(&self) -> String {
        String::from_utf8(subtle_encoding::hex::encode(
            &self.to_bytes_uncompressed()[..],
        ))
        .unwrap()
    }

    /// Convenience method when x and y are supplied separately
    pub fn decode_from_hex_points(x: &str, y: &str) -> Result<Self, String> {
        let mut s = x.to_string();
        s.push_str(y);
        Self::from_str(s.as_str())
    }

    /// Convenience method when x and y are supplied separately
    pub fn from_byte_points<B: AsRef<[u8]>>(x: B, y: B) -> Result<G1, String> {
        let a = x.as_ref();
        if a.len() != Self::COMPRESSED_BYTES {
            return Err(format!(
                "Invalid number of bytes for x. Expected '{}', supplied '{}'",
                Self::COMPRESSED_BYTES,
                a.len()
            ));
        }
        let b = y.as_ref();
        if b.len() != Self::COMPRESSED_BYTES {
            return Err(format!(
                "Invalid number of bytes for y. Expected '{}', supplied '{}'",
                Self::COMPRESSED_BYTES,
                b.len()
            ));
        }

        let x = BIG::frombytes(&a);
        let y = BIG::frombytes(&b);
        Ok(Self(ECP::new_bigs(&x, &y)))
    }

    /// Helper function for `Display` and `Debug`
    fn format(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut x = self.0.getx();
        let mut y = self.0.gety();
        write!(f, "G1 {{ x: {}, y: {} }}", x.to_hex(), y.to_hex())
    }
}

impl PartialEq<ECP> for G1 {
    fn eq(&self, other: &ECP) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &G1) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialEq<[u8; G1::COMPRESSED_BYTES]> for G1 {
    fn eq(&self, other: &[u8; G1::COMPRESSED_BYTES]) -> bool {
        self.to_bytes().ct_eq(other).unwrap_u8() == 1
    }
}

impl PartialEq<[u8; G1::UNCOMPRESSED_BYTES]> for G1 {
    fn eq(&self, other: &[u8; G1::UNCOMPRESSED_BYTES]) -> bool {
        self.to_bytes_uncompressed().ct_eq(other).unwrap_u8() == 1
    }
}

impl PartialEq<GenericArray<u8, U48>> for G1 {
    fn eq(&self, other: &GenericArray<u8, U48>) -> bool {
        self.eq(array_ref![other, 0, G1::COMPRESSED_BYTES])
    }
}

impl PartialEq<Vec<u8>> for G1 {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.eq(other.as_slice())
    }
}

impl PartialEq<[u8]> for G1 {
    fn eq(&self, other: &[u8]) -> bool {
        match other.len() {
            G1::COMPRESSED_BYTES => self.eq(array_ref![other, 0, G1::COMPRESSED_BYTES]),
            G1::UNCOMPRESSED_BYTES => self.eq(array_ref![other, 0, G1::UNCOMPRESSED_BYTES]),
            _ => false,
        }
    }
}

impl From<ECP> for G1 {
    fn from(p: ECP) -> Self {
        Self(p)
    }
}

impl From<[u8; G1::COMPRESSED_BYTES]> for G1 {
    fn from(x: [u8; G1::COMPRESSED_BYTES]) -> Self {
        Self::from(&x)
    }
}

impl From<&[u8; G1::COMPRESSED_BYTES]> for G1 {
    fn from(x: &[u8; G1::COMPRESSED_BYTES]) -> Self {
        let parity = ((x[0] >> 7) & 1) as isize;
        let mut temp = x.clone();
        temp[0] = x[0] & 0x7F;
        let x = BIG::frombytes(&temp[..]);
        Self(ECP::new_bigint(&x, parity))
    }
}

impl From<[u8; G1::UNCOMPRESSED_BYTES]> for G1 {
    fn from(points: [u8; G1::UNCOMPRESSED_BYTES]) -> Self {
        Self::from(&points)
    }
}

impl From<&[u8; G1::UNCOMPRESSED_BYTES]> for G1 {
    fn from(points: &[u8; G1::UNCOMPRESSED_BYTES]) -> Self {
        let x = BIG::frombytes(&points[..Self::COMPRESSED_BYTES]);
        let y = BIG::frombytes(&points[Self::COMPRESSED_BYTES..]);
        Self(ECP::new_bigs(&x, &y))
    }
}

/// Deserialize the point from a compressed x-coordinate in big endian form
impl From<GenericArray<u8, U48>> for G1 {
    fn from(bytes: GenericArray<u8, U48>) -> Self {
        let t: &[u8; Self::COMPRESSED_BYTES] = array_ref![bytes, 0, G1::COMPRESSED_BYTES];
        Self::from(t)
    }
}

/// Deserialize the point from x and y coordinates in big endian form
impl From<GenericArray<u8, U96>> for G1 {
    fn from(bytes: GenericArray<u8, U96>) -> Self {
        let t: &[u8; Self::UNCOMPRESSED_BYTES] = array_ref![bytes, 0, G1::UNCOMPRESSED_BYTES];
        Self::from(t)
    }
}

/// Deserialize from a hex string. If the hex string is `COMPRESSED_HEX_LENGTH`
/// It will assume compressed form––x-coordinate only.
///
/// If the hex string is `UNCOMPRESSED_HEX_LENGTH`, it assumes uncompressed form––
/// x and y coordinates
impl FromStr for G1 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This is best effort constant time execution.
        // Constant time is important as hex is used during serialization and deserialization.
        // A seemingly effortless solution is to filter string for errors and pad with 0s before
        // passing to AMCL but that would be expensive as the string is scanned twice
        let mut val = s.to_lowercase();
        // Given hex cannot be bigger than max byte size
        if val.len() > Self::UNCOMPRESSED_HEX_LENGTH {
            return Err(format!(
                "Expected length '{}', found '{}'",
                val.len(),
                Self::UNCOMPRESSED_HEX_LENGTH
            ));
        }

        // Pad the string for constant time parsing.
        if Self::COMPRESSED_HEX_LENGTH < val.len() && val.len() < Self::UNCOMPRESSED_HEX_LENGTH {
            while val.len() < Self::UNCOMPRESSED_HEX_LENGTH {
                val.insert(0, '0');
            }
        } else {
            while val.len() < Self::COMPRESSED_HEX_LENGTH {
                val.insert(0, '0');
            }
        }

        let mut bytes = match subtle_encoding::hex::decode(val) {
            Ok(b) => b,
            Err(e) => return Err(format!("{}", e)),
        };

        if bytes.len() > Self::COMPRESSED_BYTES {
            let x = BIG::frombytes(&bytes[..Self::COMPRESSED_BYTES]);
            let y = BIG::frombytes(&bytes[Self::COMPRESSED_BYTES..]);

            Ok(Self(ECP::new_bigs(&x, &y)))
        } else {
            let parity = ((bytes[0] >> 7) & 1) as isize;
            bytes[0] = bytes[0] & 0x7F;
            let x = BIG::frombytes(bytes.as_slice());
            Ok(Self(ECP::new_bigint(&x, parity)))
        }
    }
}

impl Display for G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.format(f)
    }
}

impl Debug for G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.format(f)
    }
}

fn encode_to_curve(u: BIG) -> ECP {
    let q = map_to_curve(u);
    clear_cofactor(q)
}

fn hash_to_curve(u0: BIG, u1: BIG) -> ECP {
    let mut q0 = map_to_curve(u0);
    let q1 = map_to_curve(u1);
    q0.add(&q1);
    clear_cofactor(q0)
}

/// See Section 7 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn clear_cofactor(p: ECP) -> ECP {
    p.mul(&H_EFF)
}

/// See Section 6.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn map_to_curve(u: BIG) -> ECP {
    let (x, y) = map_to_curve_simple_swu(u);
    iso_map(x, y)
}

/// See Section 6.6.2.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
///
/// Only works if p is congruent to 3 mod 4
fn map_to_curve_simple_swu(u: BIG) -> (BIG, BIG) {
    // let u = BIG::fromstring("0CCB6BDA9B602AB82AAE21C0291623E2F639648A6ADA1C76D8FFB664130FD18D98A2CC6160624148827A9726678E7CD4".to_string());
    // tv1 = Z * u^2
    let mut tv1 = BIG::modmul(&Z, &BIG::modsqr(&u, &MODULUS), &MODULUS);
    tv1.norm();
    // tv2 = tv1^2
    let mut tv2 = BIG::modsqr(&tv1, &MODULUS);
    tv2.norm();

    // x1 = tv1 + tv2
    let mut x1 = BIG::new_big(&tv1);
    x1.add(&tv2);
    x1.rmod(&MODULUS);
    x1.norm();

    // x1 = inv0(x1)
    x1.invmodp(&MODULUS);
    x1.norm();

    let e1 = if x1.iszilch() { 1 } else { 0 };

    // x1 = x1 + 1
    x1.inc(1);

    // x1 = CMOV(x1, c2, e1)
    x1.cmove(&C2, e1);

    // x1 = x1 * c1
    x1 = BIG::modmul(&x1, &C1, &MODULUS);
    x1.norm();

    // gx1 = x1^2
    let mut gx1 = BIG::modsqr(&x1, &MODULUS);
    // gx1 = gx1 + A
    gx1.add(&ISO_A);
    gx1.rmod(&MODULUS);
    gx1.norm();

    // gx1 = gx1 * x1
    gx1 = BIG::modmul(&gx1, &x1, &MODULUS);

    // gx1 = gx1 + B
    gx1.add(&ISO_B);
    gx1.rmod(&MODULUS);

    // x2 = tv1 * x1
    let mut x2 = BIG::modmul(&tv1, &x1, &MODULUS);
    x2.norm();

    // tv2 = tv1 * tv2
    tv2 = BIG::modmul(&tv1, &tv2, &MODULUS);

    // gx2 = gx1 * tv2
    let mut gx2 = BIG::modmul(&gx1, &tv2, &MODULUS);
    gx2.norm();

    // e2 = is_square(gx1)
    let e2 = if is_square(&gx1) { 1 } else { 0 };

    // x = CMOV(x2, x1, e2)
    let mut x = BIG::new_copy(&x2);
    x.cmove(&x1, e2);

    // y2 = CMOV(gx2, gx1, e2)
    let mut y2 = BIG::new_copy(&gx2);
    y2.cmove(&gx1, e2);

    // y = sqrt(y2)
    let y = sqrt_3mod4(&y2);

    // e3 = sgn0(u) == sgn0(y)
    let e3 = if sgn0(&u) == sgn0(&y) { 1 } else { 0 };

    // y = CMOV(-y, y, e3)
    let mut y_neg = BIG::modneg(&y, &MODULUS);
    y_neg.norm();
    y_neg.cmove(&y, e3);

    println!("x = {}", x.to_hex());
    println!("y = {}", y_neg.to_hex());
    (x, y_neg)
}

/// Section F.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn sqrt_3mod4(x: &BIG) -> BIG {
    let mut t = BIG::new_big(x);
    t.powmod(&SQRT_C1, &MODULUS)
}

/// is_square(x) := { True,  if x^((q - 1) / 2) is 0 or 1 in F;
///                 { False, otherwise.
fn is_square(x: &BIG) -> bool {
    let mut t = BIG::new_copy(x);
    t = t.powmod(&PM1DIV2, &MODULUS);
    let mut sum = 0;
    for i in 1..t.w.len() {
        sum |= t.w[i];
    }
    sum == 0 && (t.w[0] == 0 || t.w[0] == 1)
}

/// See Section 4.1 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn sgn0(x: &BIG) -> Ordering {
    if *x > PM1DIV2 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// See Section 4.3 in
/// <https://eprint.iacr.org/2019/403.pdf>
fn iso_map(x_prime: BIG, y_prime: BIG) -> ECP {
    let mut x_values: [BIG; 16] = [BIG::new(); 16];
    x_values[0] = BIG::new_int(1);
    x_values[1] = x_prime;
    x_values[2] = BIG::modsqr(&x_prime, &MODULUS);
    x_values[3] = BIG::modmul(&x_values[2], &x_prime, &MODULUS);
    x_values[4] = BIG::modmul(&x_values[3], &x_prime, &MODULUS);
    x_values[5] = BIG::modmul(&x_values[4], &x_prime, &MODULUS);
    x_values[6] = BIG::modmul(&x_values[5], &x_prime, &MODULUS);
    x_values[7] = BIG::modmul(&x_values[6], &x_prime, &MODULUS);
    x_values[8] = BIG::modmul(&x_values[7], &x_prime, &MODULUS);
    x_values[9] = BIG::modmul(&x_values[8], &x_prime, &MODULUS);
    x_values[10] = BIG::modmul(&x_values[9], &x_prime, &MODULUS);
    x_values[11] = BIG::modmul(&x_values[10], &x_prime, &MODULUS);
    x_values[12] = BIG::modmul(&x_values[11], &x_prime, &MODULUS);
    x_values[13] = BIG::modmul(&x_values[12], &x_prime, &MODULUS);
    x_values[14] = BIG::modmul(&x_values[13], &x_prime, &MODULUS);
    x_values[15] = BIG::modmul(&x_values[14], &x_prime, &MODULUS);

    let mut x = iso_map_helper(&x_values, &X_NUM);
    let mut x_den = iso_map_helper(&x_values, &X_DEN);
    let mut y = iso_map_helper(&x_values, &Y_NUM);
    let mut y_den = iso_map_helper(&x_values, &Y_DEN);

    x_den.invmodp(&MODULUS);
    x = BIG::modmul(&x, &x_den, &MODULUS);

    y_den.invmodp(&MODULUS);
    y = BIG::modmul(&y, &y_den, &MODULUS);
    y = BIG::modmul(&y, &y_prime, &MODULUS);

    ECP::new_bigs(&x, &y)
}

/// Compute a section of iso map
fn iso_map_helper(x: &[BIG], k: &[BIG]) -> BIG {
    let mut new_x = BIG::new();
    for i in 0..k.len() {
        let t = BIG::modmul(&x[i], &k[i], &MODULUS);
        new_x.add(&t);
        new_x.rmod(&MODULUS);
    }
    new_x
}

/// Hash to field using expand_message_xmd to compute `u` as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn hash_to_field_xmd_nu<D: BlockInput + Digest<OutputSize = U32>>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<BIG, HashingError> {
    // length_in_bytes = count * m * L = 1 * 1 * 64 = 64
    let random_bytes = expand_message_xmd::<D, L>(msg, dst)?;
    // elm_offset = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // tv = substr(random_bytes, 0, 64)
    Ok(field_elem_from_larger_bytearray(random_bytes.as_slice()))
}

/// Hash to field using expand_message_xmd to compute two `u`s as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
///
/// We avoid the loop and get compile time checking this way
fn hash_to_field_xmd_ro<D: BlockInput + Digest<OutputSize = U32>>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<(BIG, BIG), HashingError> {
    // length_in_bytes = count * m * L = 2 * 1 * 64 = 128
    let random_bytes = expand_message_xmd::<D, TwoL>(msg, dst)?;
    // elm_offset_0 = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // elm_offset_1 = L * (j + i * m) = 64 * (0 + 1 * 1) = 64
    // tv_0 = substr(random_bytes, 0, 64)
    // tv_1 = substr(random_bytes, 64, 64)
    let u_0 = field_elem_from_larger_bytearray(&random_bytes[0..L::to_usize()]);
    let u_1 = field_elem_from_larger_bytearray(&random_bytes[L::to_usize()..]);
    Ok((u_0, u_1))
}

/// Hash to field using expand_message_xof to compute `u` as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
fn hash_to_field_xof_nu<X: ExtendableOutput + Input + Reset + Default>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<BIG, HashingError> {
    // length_in_bytes = count * m * L = 1 * 1 * 64 = 64
    let random_bytes = expand_message_xof::<X, L>(msg, dst)?;
    // elm_offset = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // tv = substr(random_bytes, 0, 64)
    Ok(field_elem_from_larger_bytearray(random_bytes.as_slice()))
}

/// Hash to field using expand_message_xof to compute two `u`s as specified in Section 5.2 in
/// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
///
/// We avoid the loop and get compile time checking this way
fn hash_to_field_xof_ro<X: ExtendableOutput + Input + Reset + Default>(
    msg: &[u8],
    dst: &DomainSeparationTag,
) -> Result<(BIG, BIG), HashingError> {
    // length_in_bytes = count * m * L = 2 * 1 * 64 = 128
    let random_bytes = expand_message_xof::<X, TwoL>(msg, dst)?;
    // elm_offset_0 = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // elm_offset_1 = L * (j + i * m) = 64 * (0 + 1 * 1) = 64
    // tv_0 = substr(random_bytes, 0, 64)
    // tv_1 = substr(random_bytes, 64, 64)
    let u_0 = field_elem_from_larger_bytearray(&random_bytes[0..L::to_usize()]);
    let u_1 = field_elem_from_larger_bytearray(&random_bytes[L::to_usize()..]);
    Ok((u_0, u_1))
}

/// FIELD_ELEMENT_SIZE <= random_bytes.len() <= FIELD_ELEMENT_SIZE * 2
fn field_elem_from_larger_bytearray(random_bytes: &[u8]) -> BIG {
    // e_j = OS2IP(tv) mod p
    let mut d = DBIG::new();
    for i in random_bytes {
        d.shl(8);
        d.w[0] += *i as Chunk;
    }
    // u = (e_0, ..., e_( m - 1 ) )
    d.dmod(&MODULUS)
}

#[cfg(test)]
mod tests {
    use crate::bls381g1::{hash_to_field_xmd_nu, hash_to_field_xmd_ro, map_to_curve};
    use crate::DomainSeparationTag;
    use amcl::bls381::{big::BIG, ecp::ECP};

    #[test]
    fn map_to_curve_ro_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            // "abc",
            // "abcdef0123456789",
            // "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];

        let expected_q = [
            ("02f2686965a4dd27ccb11119f2e131aefee818744a414d23ecef4db1407991fdf058f0affaee18fd586a9ab81060ae20",
             "0341a16c88a39b3d111b36b7cf885b7147b1d54b9201faaba5b47d7839bcf433cc35bb1f7b8e55aa9382a52fe4d84370",
             "1357bddd2bc6c8e752f3cf498ffe29ae87d8ff933701ae76f82d2839b0d9aee5229d4fff54dfb8223be0d88fa4485863",
             "09ba0ec3c78cf1e65330721f777b529aef27539642c39be11f459106b890ec5eb4a21c5d94885603e822cfa765170857"),

            ("119cc1d21e3e494d388a8718fe9f8ec6d8ff134486ce5c1f97129797616c4b8125f0dc568c59836cbf064496136438bc",
             "19e6c998825ee57b82c4808e4df477680f0f254c9edce228104422494a4e5d40d11ee676f6b861b6c49cf7de9d777aef",
             "0d1783f40bd83461b921c3fcd0e9ba326ef75272b122cf44338f0060d7179995a38ea9c66f3ce800e2f693d2634a4524",
             "017b2566d55fa7ee43844f1fa068cb0a11d5889c11607d939da046697c8ba25cf71054c2a8eb2189d3680485a39f5bdd"),

            ("1614d05720a39379fb89469883f90ae3e50995def9e17f8f8566a3f6cfb4fe88267eac1dc7834406fc597965065ef100",
             "1060e5aab331ac4940693a936ea80029bb2c4a3945add7ae35bce805e767af827c4a9ffcb5842fbc50ab234716d895f6",
             "0f612cda21cee750b1ccff361a4ce047e70d9a9e152e96a60aa29b5d8a5dcd25f7c5bd71bb56bd34e6a8af7532afaa4f",
             "1878f926302468949ef290b4fee621d1172e072eda1b42e366df68fc87f53c35583dbc043009e0b38a04a9b1ff617efe"),

            ("0a817078e7f30f08e94a25c2a1947160db1fe52042626660b8252cd339e678a1fecc0e6da60390a203532bd089a426b6",
             "097bd5d6ae3f5b5d0ba5e4099485caa2c505a1d900e4525af10254b3927ae0c82611be944ff8fdc6b278aab9e17ee27c",
             "1098f203da72c58dca61ffd52a3de82603d3154c527df51c2efe6298ea0eeaa065d57ba3a809b5e32d9d56dade119006",
             "0bcbd9df3505f049476f060c1d1c958fe8b34e426fd7e75424c9e227d9c4d3edbd5eddb8b1e89cc91b4a7bd3275d4d70"),
        ];

        for i in 0..msgs.len() {
            let u = hash_to_field_xmd_ro::<sha2::Sha256>(msgs[i].as_bytes(), &dst).unwrap();
            let exp_q = ECP::new_bigs(
                &BIG::from_hex(expected_q[i].0.to_string()),
                &BIG::from_hex(expected_q[i].1.to_string()),
            );
            let actual_q = map_to_curve(u.0);
            assert_eq!(exp_q, actual_q);
            let exp_q = ECP::new_bigs(
                &BIG::from_hex(expected_q[i].2.to_string()),
                &BIG::from_hex(expected_q[i].3.to_string()),
            );
            let actual_q = map_to_curve(u.1);
            assert_eq!(exp_q, actual_q);
        }
    }

    // Take from section G.9.2
    #[test]
    fn map_to_curve_nu_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_NU_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let q_s = [
            ("0dddf77f320e7848a457358ab8d3b84cbaf19307be26b91a10c211651691cd736b1f59d77aed3954f857f108d6966f5b", "0450ab32020649f22a2fca166a1d8a59d4c93f1eb078a4bedd6c48027b9933507a2a8ae4d915305f58ede781283325a9"),
            ("12897a9a513b12303a7f0f3a3cc7c838d16847a31507980945312bede915848159bd390b16b8e378b398e31a385d9180", "1372530cc0811d70071e50640281aa8aaf96ee09c01281ccfead92296cb9dacf5054aa51dbea730e46239e709042a15d"),
            ("08459bd42a955d6e247fce6c81eda0ad9645f9e666d141a71f0afa3fbc509b2c58550fe077d073cc752493400399fddd", "169d35a8c6bb915ae910f4c6cde359622746b0c8b2b241b411d0e92ef991d3e6a7b0fafabb93c1de2e3997d6e362ce8a"),
            ("08c937d529c01ab2398b85b0bff6da465ed6265d4944dbbef7d383eea40157927082739c7b5417027d2225c6cb9d5ef0", "059047d83b5ea1ff7f0665b406acede27f233d3414055cbff25b37614b679f08fd6d807b5956edec6abad36c5321d99e"),
        ];

        for i in 0..msgs.len() {
            let u = hash_to_field_xmd_nu::<sha2::Sha256>(msgs[i].as_bytes(), &dst).unwrap();
            let expected_q = ECP::new_bigs(
                &BIG::from_hex(q_s[i].0.to_string()),
                &BIG::from_hex(q_s[i].1.to_string()),
            );
            let actual_q1 = map_to_curve(u);
            assert_eq!(expected_q, actual_q1);
        }
    }

    // Take from section G.9.2
    #[test]
    fn hash_to_field_xmd_nu_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_NU_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let executed_u_s = [
            "0ccb6bda9b602ab82aae21c0291623e2f639648a6ada1c76d8ffb664130fd18d98a2cc6160624148827a9726678e7cd4",
            "08accd9a1bd4b75bb2e9f014ac354a198cbf607f0061d00a6286f5544cf4f9ecc1439e3194f570cbbc7b96d1a754f231",
            "0a359cf072db3a39acf22f086d825fcf49d0daf241d98902342380fc5130b44e55de8f684f300bc11c44dee526413363",
            "181d09392c52f7740d5eaae52123c1dfa4808343261d8bdbaf19e7773e5cdfd989165cd9ecc795500e5da2437dde2093",
        ];

        for i in 0..msgs.len() {
            let expected_u = BIG::from_hex(executed_u_s[i].to_string());
            let actual_u = hash_to_field_xmd_nu::<sha2::Sha256>(msgs[i].as_bytes(), &dst);
            assert!(actual_u.is_ok());
            assert_eq!(actual_u.unwrap(), expected_u);
        }
    }

    // Take from section G.9.1
    #[test]
    fn hash_to_field_xmd_ro_tests() {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Some(b"TESTGEN"),
            None,
            None,
        )
        .unwrap();
        let msgs = [
            "",
            "abc",
            "abcdef0123456789",
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ];
        let expected_u_s = [
            ("14700e34d15178550475044b044b4e41ca8d52a655c34f8afea856d21d499f48c9370d2bae4ae8351305493e48d36ab5", "17e2da57f6fd3f11dba6119db4cd26b03e63e67b4e42db678d9c41fdfcaff00ba336d8563abcd9da6c17d2e1784ee858"),
            ("10c84aa245c74ee20579a27e63199be5d19cdfb5e44c6b587765931605d7790a1df6e1433f78bcddb4edb8553374f75e", "0f73433dcc2b5f9905c49d905bd62e1a1529b057c77194e56d196860d9d645167e0430aec9d3c70de31dd046fcab4a20"),
            ("11503eb4a558d0d2c5fc7cdddb51ba715c33577cf1a7f2f21a7eee6d2a570332bbbe53ae3392c9f8d8f6c172ae484692", "0efd59b8d98be7c491dfdb9d2a669e32e9bb348f8a64dbf7e47708dd5d40f484b1439109a3f96230bf63af72b908c43d"),
            ("134dc7f817cc08c5a3128892385ff6e9dd55f5e39d9a2d74ac74058d5dfc025d507806ab5d9254bd2334defbb477400d", "0eeaf2c6f4c1ca5cc039d99cb94234f67e65968f36d9dd77e95da55dadd085b50fbb11489167ded9157e5aac0d99d5be"),
        ];

        for i in 0..msgs.len() {
            let expected_u0 = BIG::from_hex(expected_u_s[i].0.to_string());
            let expected_u1 = BIG::from_hex(expected_u_s[i].1.to_string());
            let res = hash_to_field_xmd_ro::<sha2::Sha256>(msgs[i].as_bytes(), &dst);
            assert!(res.is_ok());
            let (actual_u0, actual_u1) = res.unwrap();
            assert_eq!(actual_u0, expected_u0);
            assert_eq!(actual_u1, expected_u1);
        }
    }
}
