pub(crate) trait IsogenyMap<T> {
    fn a(&self) -> T;
    fn b(&self) -> T;
    fn z(&self) -> T;
    fn x_num(&self) -> &[T];
    fn x_den(&self) -> &[T];
    fn y_num(&self) -> &[T];
    fn y_den(&self) -> &[T];
}

#[cfg(all(feature = "bls", target_pointer_width = "64"))]
#[path = "bls381g1_64.rs"]
pub mod bls381g1;
#[cfg(all(feature = "bls", target_pointer_width = "32"))]
#[path = "bls381g1_32.rs"]
pub mod bls381g1;

// #[cfg(all(feature = "bls", target_pointer_width = "64"))]
// #[path = "bls381g2_64.rs"]
// pub mod bls381g2;
//
// #[cfg(all(feature = "bls", target_pointer_width = "32"))]
// #[path = "bls381g2_32.rs"]
// pub mod bls381g2;
