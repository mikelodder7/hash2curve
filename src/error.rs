use failure::{Backtrace, Context, Fail};

use std::fmt;

/// A specific type of error
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum HashingErrorKind {
    /// Parsing error when using from_bytes
    #[fail(display = "Parsing error")]
    ParseError,
    /// If the domain separation tag is too long or too short
    #[fail(display = "Invalid domain separation tag")]
    InvalidDomainSeparationTag,
    ///
    #[fail(display = "Requested invalid bytes from expand message xmd")]
    InvalidXmdRequestLength,
}

/// Represents an error within a context
#[derive(Debug)]
pub struct HashingError {
    /// Represents the context that generated the error
    inner: Context<HashingErrorKind>,
}

impl HashingError {
    /// Convert from a static string like structure
    pub fn from_msg<D: fmt::Display + fmt::Debug + Send + Sync + 'static>(
        kind: HashingErrorKind,
        msg: D,
    ) -> Self {
        Self {
            inner: Context::new(msg).context(kind),
        }
    }

    /// Get the inner HashingErroKind
    pub fn kind(&self) -> HashingErrorKind {
        *self.inner.get_context()
    }
}

impl Fail for HashingError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for HashingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for cause in Fail::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }

        Ok(())
    }
}

impl From<Context<HashingErrorKind>> for HashingError {
    fn from(inner: Context<HashingErrorKind>) -> HashingError {
        HashingError { inner }
    }
}
