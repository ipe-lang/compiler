//! The runtime's host hooks for the shared scratch primitive in `scratch_core`.
//!
//! `scratch_core` is the single scratch implementation, shared verbatim with
//! the compiler sandbox; this module supplies what differs per host: the
//! entropy source, the profile variable name, and the profile directory.

use super::scratch_core::EntropyUnavailable;

pub use super::home_core::HomeDir;

/// The variable naming the current user's profile directory on Windows.
pub const PROFILE_VAR: &str = super::home_core::WINDOWS_HOME_VAR;

/// Fill `buf` from the OS CSPRNG.
///
/// # Errors
/// [`EntropyUnavailable`] when the OS random source cannot be read.
pub fn fill_entropy(buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
    getrandom::getrandom(buf).map_err(|e| EntropyUnavailable {
        detail: e.to_string(),
    })
}

/// The current user's profile directory, which off Unix must contain every scratch base.
#[cfg(not(unix))]
#[must_use]
pub fn profile_dir() -> Option<HomeDir> {
    super::system::home_dir().ok()
}
