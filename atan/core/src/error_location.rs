//! Error location tracking for debugging

use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct ErrorLocation {
    file: String,
    line: String,
}

impl ErrorLocation {
    #[track_caller]
    pub fn capture() -> Self {
        let location = std::panic::Location::caller();
        Self { file: location.file().to_string(), line: location.line().to_string() }
    }
}

impl Display for ErrorLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error occurred at {}::{}", self.file, self.line)
    }
}
