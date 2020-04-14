pub(crate) trait IsogenyMap<T> {
    fn a(&self) -> T;
    fn b(&self) -> T;
    fn z(&self) -> T;
    fn x_num(&self) -> &[T];
    fn x_den(&self) -> &[T];
    fn y_num(&self) -> &[T];
    fn y_den(&self) -> &[T];
}

#[cfg(feature = "bls")]
pub mod bls381g1;

#[cfg(feature = "bls")]
pub mod  bls381g2;
