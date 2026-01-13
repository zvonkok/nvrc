// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Error handling for NVRC.
//!
//! Provides anyhow-like API for consistent error handling.

extern crate alloc;

use alloc::string::String;
use core::fmt;

/// Error type for NVRC - simple wrapper around a message string
#[derive(Debug)]
pub struct Error {
    msg: String,
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

/// Convert from hardened_std::Error
impl From<hardened_std::Error> for Error {
    fn from(e: hardened_std::Error) -> Self {
        Error::new(alloc::format!("{}", e))
    }
}

/// Convert from core::num::ParseIntError
impl From<core::num::ParseIntError> for Error {
    fn from(e: core::num::ParseIntError) -> Self {
        Error::new(alloc::format!("parse error: {:?}", e))
    }
}

/// Result type alias
pub type Result<T> = core::result::Result<T, Error>;

/// Context trait for adding context to errors
pub trait Context<T> {
    fn context(self, msg: &'static str) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for core::result::Result<T, E> {
    fn context(self, msg: &'static str) -> Result<T> {
        self.map_err(|e| {
            let inner: Error = e.into();
            Error::new(alloc::format!("{}: {}", msg, inner.msg))
        })
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| {
            let inner: Error = e.into();
            Error::new(alloc::format!("{}: {}", f(), inner.msg))
        })
    }
}

/// Create an error with a formatted message
#[macro_export]
macro_rules! anyhow {
    ($($arg:tt)*) => {
        $crate::error::Error::new(alloc::format!($($arg)*))
    };
}
