//! Implements hash to curve as described in Section 8.7.2 of
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//! and Section 5 of
//!  <https://eprint.iacr.org/2019/403.pdf>
//!
//! G2 has to deal with `I` since its in Fp^2. So
//!
//! I^2 = -1 mod p or (p - 1) mod p which means that `I`
//! can be represented at sqrt(p - 1) mod p

use amcl::bls381::{big::BIG, fp2::FP2};

type L = U64;
type TwoL = U128;
use digest::{
    generic_array::typenum::{marker_traits::Unsigned, U128, U32, U64},
    BlockInput, Digest, ExtendableOutput, Input, Reset,
};
