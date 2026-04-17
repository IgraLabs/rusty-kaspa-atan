use crate::error_location::ErrorLocation;
use kaspa_hashes::Hash;
use std::fmt::{Debug, Display};

pub type AtanResult<T> = Result<T, AtanError>;

#[derive(Debug, Clone)]
pub enum AtanError {
    Validation(ValidationError),
    System(SystemError),
}

#[derive(Debug, Clone)]
pub enum ValidationError {
    #[error("{2}: Invalid sequencing commitment: Expected: {0}, Actual: {1}")]
    InvalidSequencingCommitment(Expected<Hash>, Actual<Hash>, ErrorLocation),
}

#[derive(Debug, Clone)]
pub enum SystemError {}

/// Wraps the expected value in an error.
#[derive(Debug, Clone, PartialEq)]
pub struct Expected<T>(pub T);

/// Wraps the actual value in an error.
#[derive(Debug, Clone, PartialEq)]
pub struct Actual<T>(pub T);

impl<T: Debug> Display for Actual<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Actual: {:?}", self.0)
    }
}

impl<T: Debug> Display for Expected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Expected: {:?}", self.0)
    }
}

impl PartialEq<Hash> for Expected<Hash> {
    fn eq(&self, other: &Hash) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Hash> for Actual<Hash> {
    fn eq(&self, other: &Hash) -> bool {
        self.0 == *other
    }
}
