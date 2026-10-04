//! The one audited reader of the process environment for compiler-side code.
//!
//! The root `clippy.toml` denies `std::env::{var, var_os, vars, vars_os}`
//! workspace-wide, so every environment read in a crate governed by it routes
//! through [`var`] / [`var_os`] here (or carries a per-site
//! `#[allow(clippy::disallowed_methods)]` in a file the `home_read_scan` test
//! pins as audited). The two readers mirror their `std` namesakes except that a
//! home or temp-root variable is never returned. The invoking user's home is
//! attacker-reachable input that decides where caches and scratch roots live,
//! and its one validated reader is `ipe_sandbox::home::home_dir` (a parsed
//! `HomeDir` or a typed refusal). The temp root (`TMPDIR`, `TMP`, `TEMP`) names
//! a base other users can write, and its one reader is the scratch primitive,
//! which verifies the base and creates entries exclusively under it. A refused
//! read through this crate — by literal, by a constant, or by a key computed at
//! runtime — answers as unset, so no spelling of the key reaches the raw value.
//! There is no whole-environment iterator: an iteration would hand a refused
//! value out under its own name.

pub mod artifact;

use std::env::VarError;
use std::ffi::{OsStr, OsString};

/// Variables that name (a part of) the invoking user's home directory.
///
/// Compared case-insensitively under every Unicode case mapping: Windows
/// environment names fold case through a Unicode upcase table, so `Home`, or a
/// spelling whose `ı` / `ſ` / `İ` folds onto an ASCII letter, can read the same
/// value as `HOME` there.
pub const HOME_NAMES: [&str; 4] = ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"];

/// Variables that name the OS temp root, a base other local users can write.
///
/// Compared like [`HOME_NAMES`]. Only the scratch primitive resolves the temp
/// root, through the standard library's own lookup behind its ownership and
/// exclusive-create checks.
pub const TEMP_ROOT_NAMES: [&str; 3] = ["TMPDIR", "TMP", "TEMP"];

/// `c` folded onto the ASCII letter its uppercase or lowercase mapping starts
/// with, or `c` itself when neither mapping reaches ASCII.
fn ascii_fold(c: char) -> char {
    c.to_uppercase()
        .next()
        .filter(char::is_ascii_alphabetic)
        .or_else(|| c.to_lowercase().next().filter(char::is_ascii_alphabetic))
        .unwrap_or(c)
}

/// Whether `key` spells one of `names` under any case mapping.
///
/// Fails closed: a key matches when its per-character ASCII fold or its full
/// Unicode uppercase equals a name, ASCII case ignored.
fn spells_any(key: &OsStr, names: &[&str]) -> bool {
    let key = key.to_string_lossy();
    let folded: String = key.chars().map(ascii_fold).collect();
    let upper = key.to_uppercase();
    names
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&folded) || n.eq_ignore_ascii_case(&upper))
}

/// Whether `key` names a home variable this crate refuses to read.
#[must_use]
pub fn is_home_key(key: &OsStr) -> bool {
    spells_any(key, &HOME_NAMES)
}

/// Whether `key` names a temp-root variable this crate refuses to read.
#[must_use]
pub fn is_temp_root_key(key: &OsStr) -> bool {
    spells_any(key, &TEMP_ROOT_NAMES)
}

/// Whether this crate refuses to read `key`: a home or a temp-root variable.
#[must_use]
pub fn is_refused_key(key: &OsStr) -> bool {
    is_home_key(key) || is_temp_root_key(key)
}

/// The UTF-8 value of `key`, as `std::env::var` — `NotPresent` for a refused key.
///
/// # Errors
///
/// `VarError::NotPresent` when `key` is unset or is refused
/// ([`is_refused_key`]), and
/// `VarError::NotUnicode` when its value is not valid UTF-8.
#[allow(clippy::disallowed_methods)] // the audited reader: refused keys answered first
pub fn var<K: AsRef<OsStr>>(key: K) -> Result<String, VarError> {
    let key = key.as_ref();
    if is_refused_key(key) {
        return Err(VarError::NotPresent);
    }
    std::env::var(key)
}

/// The raw value of `key`, as `std::env::var_os` — `None` for a refused key.
#[must_use]
#[allow(clippy::disallowed_methods)] // the audited reader: refused keys answered first
pub fn var_os<K: AsRef<OsStr>>(key: K) -> Option<OsString> {
    let key = key.as_ref();
    if is_refused_key(key) {
        return None;
    }
    std::env::var_os(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_a_home_key_is_refused() {
        for key in [
            "HOME",
            "home",
            "Home",
            "USERPROFILE",
            "UserProfile",
            "HOMEDRIVE",
            "HOMEPATH",
            "homepath",
        ] {
            assert!(is_home_key(OsStr::new(key)), "{key:?}");
            assert_eq!(var_os(key), None, "{key:?}");
            assert_eq!(var(key), Err(VarError::NotPresent), "{key:?}");
        }
    }

    #[test]
    fn a_unicode_spelling_that_folds_onto_a_home_key_is_refused() {
        for key in [
            "USERPROF\u{0131}LE", // dotless i uppercases to `I`
            "u\u{017F}erprofile", // long s uppercases to `S`
            "U\u{017F}ERPROF\u{0131}LE",
            "HOMEDR\u{0130}VE", // dotted capital I lowercases to `i`
            "homedr\u{0131}ve",
        ] {
            assert!(is_home_key(OsStr::new(key)), "{key:?}");
            assert_eq!(var_os(key), None, "{key:?}");
            assert_eq!(var(key), Err(VarError::NotPresent), "{key:?}");
        }
    }

    #[test]
    fn a_home_key_held_in_a_runtime_value_is_refused() {
        let computed: String = ["HO", "ME"].concat();
        assert_eq!(var_os(&computed), None);
        assert_eq!(var(OsString::from(computed)), Err(VarError::NotPresent));
    }

    #[test]
    fn every_spelling_of_a_temp_root_key_is_refused() {
        for key in [
            "TMPDIR", "tmpdir", "TmpDir", "TMP", "tmp", "TEMP", "Temp", "temp",
        ] {
            assert!(is_temp_root_key(OsStr::new(key)), "{key:?}");
            assert!(is_refused_key(OsStr::new(key)), "{key:?}");
            assert_eq!(var_os(key), None, "{key:?}");
            assert_eq!(var(key), Err(VarError::NotPresent), "{key:?}");
        }
    }

    #[test]
    fn a_temp_root_key_held_in_a_constant_or_runtime_value_is_refused() {
        const K: &str = "TMPDIR";
        assert_eq!(var_os(K), None);
        assert_eq!(var_os(OsStr::new(K)), None);
        let computed: String = ["TM", "PDIR"].concat();
        assert_eq!(var_os(&computed), None);
        assert_eq!(var(OsString::from(computed)), Err(VarError::NotPresent));
    }

    #[test]
    fn a_neighbouring_temp_key_is_not_refused() {
        for key in [
            "TMPDIR_",
            "IPE_TMP",
            "TEMPLATE",
            "CARGO_TARGET_TMPDIR",
            "TM",
        ] {
            assert!(!is_temp_root_key(OsStr::new(key)), "{key:?}");
            assert!(!is_refused_key(OsStr::new(key)), "{key:?}");
        }
    }

    #[test]
    fn a_neighbouring_key_is_not_refused() {
        for key in [
            "HOMEBREW_PREFIX",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "XDG_CACHE_HOME",
            "HOME_",
            "",
        ] {
            assert!(!is_home_key(OsStr::new(key)), "{key:?}");
        }
    }

    #[test]
    fn a_non_home_key_reads_as_std_does() {
        #[allow(clippy::disallowed_methods)] // the oracle this reader must mirror
        let raw = std::env::var_os("CARGO_MANIFEST_DIR");
        assert_eq!(var_os("CARGO_MANIFEST_DIR"), raw);
        assert_eq!(
            var("CARGO_MANIFEST_DIR").ok(),
            raw.and_then(|v| v.into_string().ok())
        );
    }
}
