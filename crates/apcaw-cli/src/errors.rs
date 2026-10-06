// SPDX-License-Identifier: BSD-2-Clause
//! Command-line errors and exit codes (the Python CLI's, plus 130).
//!
//! * 0: success, or VERIFIED
//! * 1: NOT VERIFIED, signing failed, selftest failed
//! * 2: usage error (bad arguments, malformed key, message too long, output exists)
//! * 3: I/O error (unreadable input or key, undecodable audio, ffmpeg, write failure)
//! * 130: interrupted

use std::fmt;
use std::io;

use crate::report::py_repr;

/// Success, VERIFIED.
pub const EXIT_OK: i32 = 0;
/// NOT VERIFIED, signing failed, selftest failed.
pub const EXIT_FAIL: i32 = 1;
/// Usage error.
pub const EXIT_USAGE: i32 = 2;
/// I/O error.
pub const EXIT_IO: i32 = 3;
/// Interrupted (SIGINT).
pub const EXIT_INTERRUPTED: i32 = 130;

/// A failure that ends a command; the message is printed as `apcaw: {msg}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Exit 1: a signing that did not produce a verifying file.
    Fail(String),
    /// Exit 2: bad arguments or key material.
    Usage(String),
    /// Exit 3: files, pipes and external tools.
    Io(String),
}

/// Result of a command.
pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    pub fn fail(msg: impl Into<String>) -> Self {
        CliError::Fail(msg.into())
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        CliError::Usage(msg.into())
    }

    pub fn io(msg: impl Into<String>) -> Self {
        CliError::Io(msg.into())
    }

    pub fn code(&self) -> i32 {
        match self {
            CliError::Fail(_) => EXIT_FAIL,
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Io(_) => EXIT_IO,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            CliError::Fail(m) | CliError::Usage(m) | CliError::Io(m) => m,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CliError {}

/// The C `strerror` text of an I/O error (Python's `OSError.strerror`):
/// Rust's `"No such file or directory (os error 2)"` without the suffix.
pub fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    match (e.raw_os_error(), s.rfind(" (os error ")) {
        (Some(_), Some(i)) => s[..i].to_string(),
        _ => s,
    }
}

/// `str(OSError)` of Python for a failed operation on `path`:
/// `[Errno 13] Permission denied: 'path'`.
pub fn py_os_error(e: &io::Error, path: &str) -> String {
    match e.raw_os_error() {
        Some(n) => format!("[Errno {n}] {}: {}", strerror(e), py_repr(path)),
        None => strerror(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_error_texts() {
        let e = io::Error::from_raw_os_error(2);
        assert_eq!(strerror(&e), "No such file or directory");
        assert_eq!(py_os_error(&e, "a/b.key"), "[Errno 2] No such file or directory: 'a/b.key'");
        let e = io::Error::other("boom");
        assert_eq!(strerror(&e), "boom");
    }
}
