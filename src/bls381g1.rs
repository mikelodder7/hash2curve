//! Implements hash to curve as described in Section 8.7.1 of
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//! and Section 5 of
//!  <https://eprint.iacr.org/2019/403.pdf>

use amcl_wrapper::{
    constants::{GroupG1_SIZE as G1Size, MODBYTES as FieldElementSize},
    field_elem::FieldElement,
    group_elem::GroupElement,
    group_elem_g1::G1,
};

#[derive(Clone, Debug)]
pub struct Hash(G1);