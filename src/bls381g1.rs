//! Implements hash to curve as described in Section 8.7.1 of
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//! and Section 5 of
//!  <https://eprint.iacr.org/2019/403.pdf>


use crate::{DomainSeparationTag, expand_message_xmd};
use crate::error::HashingError;
use amcl_wrapper::{field_elem::FieldElement, constants::CURVE_ORDER, types::{DoubleBigNum, Limb}};
use digest::{Digest, BlockInput, generic_array::{GenericArray, ArrayLength, typenum::{U32, U64, U128}}};

/// To compute a `L` use the following formula
/// L = ceil(ceil(log2(p) + k) / 8). For example, in our case log2(p) = 381, k = 128
/// L = 64
fn hash_to_field_xmd_1<M: AsRef<[u8]>, D: BlockInput + Digest<OutputSize = U32>>(msg: M, dst: &DomainSeparationTag) -> Result<FieldElement, HashingError> {
    // length_in_bytes = count * m * L = 1 * 1 * 64 = 64
    let random_bytes = expand_message_xmd::<M, D, U64>(msg, dst)?;
    // elm_offset = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // tv = substr(random_bytes, 0, 64)
    Ok(field_elem_from_larger_bytearray(random_bytes.as_slice()))
}

/// To compute a `L` use the following formula
/// L = ceil(ceil(log2(p) + k) / 8). For example, in our case log2(p) = 381, k = 128
/// L = 64
fn hash_to_field_xmd_2<M: AsRef<[u8]>, D: BlockInput + Digest<OutputSize = U32>>(msg: M, dst: &DomainSeparationTag) -> Result<(FieldElement, FieldElement), HashingError> {
    // length_in_bytes = count * m * L = 2 * 1 * 64 = 128
    let random_bytes = expand_message_xmd::<M, D, U128>(msg, dst)?;
    // elm_offset_0 = L * (j + i * m) = 64 * (0 + 0 * 1) = 0
    // elm_offset_1 = L * (j + i * m) = 64 * (0 + 1 * 1) = 64
    // tv_0 = substr(random_bytes, 0, 64)
    // tv_1 = substr(random_bytes, 64, 64)
    let u_0 = field_elem_from_larger_bytearray(&random_bytes[0..64]);
    let u_1 = field_elem_from_larger_bytearray(&random_bytes[64..128]);
    Ok((u_0, u_1))
}

/// FIELD_ELEMENT_SIZE <= random_bytes.len() <= FIELD_ELEMENT_SIZE * 2
fn field_elem_from_larger_bytearray(random_bytes: &[u8]) -> FieldElement {
    // e_j = OS2IP(tv) mod p
    let mut d = DoubleBigNum::new();
    for i in 0..random_bytes.len() {
        d.shl(8);
        d.w[0] += random_bytes[i] as Limb;
    }
    // u = (e_0, ..., e_( m - 1 ) )
    let u = d.dmod(&CURVE_ORDER);
    FieldElement::from(u)
}

#[cfg(test)]
mod tests {
    use crate::DomainSeparationTag;
    use amcl_wrapper::field_elem::FieldElement;
    use crate::bls381g1::{hash_to_field_xmd_1, hash_to_field_xmd_2};
    use amcl_wrapper::errors::SerzDeserzError::FieldElementBytesIncorrectSize;

    // Take from section G.9.2
    #[test]
    fn hash_to_field_xmd_1_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_NU_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msg = "";
        let expected_u = FieldElement::from_hex("0ccb6bda9b602ab82aae21c0291623e2f639648a6ada1c76d8ffb664130fd18d98a2cc6160624148827a9726678e7cd4".to_string()).unwrap();
        let actual_u = hash_to_field_xmd_1::<&str, sha2::Sha256>(msg, &dst);
        assert!(actual_u.is_ok());
        assert_eq!(actual_u.unwrap(), expected_u);
    }

    #[test]
    fn hash_to_field_xmd_2_tests() {
        let dst = DomainSeparationTag::new("BLS12381G1_XMD:SHA-256_SSWU_RO_",
                                           Some("TESTGEN"),
                                           None,
                                           None).unwrap();
        let msg = "";
        let expected_u0 = FieldElement::from_hex("14700e34d15178550475044b044b4e41ca8d52a655c34f8afea856d21d499f48c9370d2bae4ae8351305493e48d36ab5".to_string()).unwrap();
        let expected_u1 = FieldElement::from_hex("17e2da57f6fd3f11dba6119db4cd26b03e63e67b4e42db678d9c41fdfcaff00ba336d8563abcd9da6c17d2e1784ee858".to_string()).unwrap();
        let res = hash_to_field_xmd_2::<&str, sha2::Sha256>(msg, &dst);
        assert!(res.is_ok());
        let (actual_u0, actual_u1) = res.unwrap();
        assert_eq!(actual_u0, expected_u0);
        assert_eq!(actual_u1, expected_u1);
    }
}