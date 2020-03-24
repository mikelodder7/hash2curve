/// Evaluate isogeny map from curve with non-zero j-invariant.
pub trait IsogenyMap {
    /// Evaluate isogeny map
    fn isogeny_map(&mut self);
}



#[cfg(feature = "bls")]
pub mod bls381g1;