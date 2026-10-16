//! The runtime's host hooks for the shared scratch primitive in `scratch_core`.
//!
//! `scratch_core` is the single scratch implementation, shared verbatim with
//! the compiler sandbox; this module supplies what differs per host: the
//! entropy source, the profile variable name, and the profile directory.

use super::scratch_core::EntropyUnavailable;

pub use super::home_core::{HomeDir, HomeRefusal};

/// The variable naming the current user's profile directory on Windows.
pub const PROFILE_VAR: &str = super::home_core::WINDOWS_HOME_VAR;

/// Fill `buf` from the runtime's one OS random source.
///
/// # Errors
/// [`EntropyUnavailable`] when the OS random source cannot be read.
pub fn fill_entropy(buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
    fill_with(super::entropy::fill_entropy, buf)
}

/// Fill `buf` through `fill`, naming a refusal as [`EntropyUnavailable`].
fn fill_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), super::entropy::EntropyError>,
    buf: &mut [u8],
) -> Result<(), EntropyUnavailable> {
    fill(buf).map_err(|e| EntropyUnavailable {
        detail: e.to_string(),
    })
}

/// The current user's profile directory, which off Unix must contain every scratch base.
///
/// # Errors
/// The [`HomeRefusal`] the profile variable earns.
#[cfg(not(unix))]
pub fn profile_dir() -> Result<HomeDir, HomeRefusal> {
    super::system::home_dir()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// A refused draw surfaces as [`EntropyUnavailable`] naming the source.
    #[test]
    fn entropy_failure_maps() {
        let mut buf = [0_u8; 8];
        let refused = fill_with(|_| Err(super::super::entropy::EntropyError), &mut buf);
        assert_eq!(
            refused.map_err(|e| e.detail),
            Err("the OS random source is unavailable".to_owned())
        );
        assert!(fill_entropy(&mut buf).is_ok(), "the test host has entropy");
    }
}
