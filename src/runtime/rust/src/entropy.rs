//! The runtime's one source of OS entropy.
//!
//! Every random mint in the runtime (session ids, CSRF tokens, style nonces,
//! UUIDs, token `jti`s, AEAD nonces, scratch names) draws through
//! [`fill_entropy`]. A draw is fallible: a host without entropy refuses with
//! [`EntropyError`], never a panic and never a weaker substitute value.

use std::fmt;

/// Why bytes could not be drawn from the OS random source.
///
/// Fieldless, so no OS error detail reaches a response body or a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the OS random source is unavailable")
    }
}

impl std::error::Error for EntropyError {}

/// Fill `buf` with bytes from the OS CSPRNG.
///
/// # Errors
///
/// [`EntropyError`] when the OS random source refuses the draw.
#[expect(clippy::disallowed_methods)] // the runtime's one entropy source
pub fn fill_entropy(buf: &mut [u8]) -> Result<(), EntropyError> {
    getrandom::getrandom(buf).map_err(|_| EntropyError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draw_succeeds() {
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        assert_eq!(fill_entropy(&mut first), Ok(()));
        assert_eq!(fill_entropy(&mut second), Ok(()));
        assert_ne!(first, second, "two 256-bit draws must differ");
    }

    #[test]
    fn error_names_the_source_without_detail() {
        assert_eq!(
            EntropyError.to_string(),
            "the OS random source is unavailable"
        );
    }
}
