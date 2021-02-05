/// Implements the error types this crate produces
use crate::lib::*;

/// The kinds of errors
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Occurs when ell > 255 in expand_msg_xmd
    TooManyBytesRequest,
}
