use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Io = 1,
    Usage = 2,
    Integrity = 3,
    Limit = 4,
    Execution = 5,
}

#[derive(Debug)]
pub struct AppError {
    pub class: ExitClass,
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    pub fn new(class: ExitClass, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            code,
            message: message.into(),
        }
    }

    pub fn io(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Io, code, message)
    }

    pub fn usage(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Usage, code, message)
    }

    pub fn limit(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Limit, code, message)
    }

    pub fn execution(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Execution, code, message)
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

#[derive(Debug, Serialize)]
pub struct ErrorDocument<'a> {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub code: &'a str,
    pub message: &'a str,
    pub exit_code: u8,
}

impl<'a> From<&'a AppError> for ErrorDocument<'a> {
    fn from(error: &'a AppError) -> Self {
        Self {
            schema_version: "cmdtrail.error.v1",
            tool_version: crate::VERSION,
            code: error.code,
            message: &error.message,
            exit_code: error.class as u8,
        }
    }
}
