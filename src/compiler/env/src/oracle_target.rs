//! The one parser of a shared cargo target directory value.
//!
//! Test harnesses and the test-only self-runs (the `ipe doc` example gate, the
//! coverage probe) link emitted builds against a warm shared target named by
//! [`SHARED_VAR`]. Every reader parses the raw value here, so a blank or
//! relative value is refused the same way everywhere instead of being read as
//! "no shared target" by one reader and as a path by another.

use std::fmt;
use std::path::{Path, PathBuf};

/// The variable CI sets to the warm shared target every E2E build links from.
pub const SHARED_VAR: &str = "IPE_ORACLE_SHARED_TARGET";

/// An absolute directory a build may share its dependency tree through.
///
/// Built only by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedTarget(PathBuf);

impl SharedTarget {
    /// The absolute directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The absolute directory, owned.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// Why a raw value is not a [`SharedTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The value is blank or not an absolute path for this host.
    NotAbsolute,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the value is not an absolute path"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse `raw` (surrounding whitespace ignored) into a [`SharedTarget`].
///
/// # Errors
///
/// [`ParseError::NotAbsolute`] when the trimmed value is empty or relative for
/// this host; a relative value is never resolved against a working directory.
pub fn parse(raw: &str) -> Result<SharedTarget, ParseError> {
    let trimmed = raw.trim();
    let path = Path::new(trimmed);
    if trimmed.is_empty() || !path.is_absolute() {
        return Err(ParseError::NotAbsolute);
    }
    Ok(SharedTarget(path.to_path_buf()))
}

/// The shared target named by [`SHARED_VAR`] in this process's environment.
///
/// `Ok(None)` when the variable is unset or empty.
///
/// # Errors
///
/// [`ParseError::NotAbsolute`] when it is set to a blank-but-not-empty or a
/// relative value.
pub fn from_env() -> Result<Option<SharedTarget>, ParseError> {
    match crate::var(SHARED_VAR) {
        Ok(raw) if !raw.is_empty() => parse(&raw).map(Some),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, SharedTarget, parse};
    use std::path::Path;

    /// An absolute path spelled for this host.
    const fn host_absolute() -> &'static str {
        if cfg!(windows) {
            r"C:\shared\target"
        } else {
            "/shared/target"
        }
    }

    #[test]
    fn absolute_value_parses_trimmed() {
        let raw = format!("  {}\n", host_absolute());
        assert_eq!(
            parse(&raw).map(SharedTarget::into_path_buf),
            Ok(Path::new(host_absolute()).to_path_buf())
        );
    }

    #[test]
    fn blank_and_relative_values_are_refused() {
        for raw in [
            "",
            " ",
            "\t\n",
            ".",
            "target",
            "./target",
            "../target",
            "C:foo",
            r"\shared\target",
        ] {
            assert_eq!(parse(raw), Err(ParseError::NotAbsolute), "{raw:?}");
        }
    }
}
