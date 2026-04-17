pub type AtanResult<T> = Result<T, AtanError>;

pub enum AtanError {
    ValidationError(ValidationError),
    SystemError(SystemError),
}

pub enum ValidationError {}
pub enum SystemError {}