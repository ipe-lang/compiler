//! Private scratch directories and files, the one primitive every temporary write goes through.
//!
//! A scratch path is handed to external writers (`curl -o`, `sh`, the jail) that
//! re-resolve it by name, so it is only safe while no other user can read,
//! predict, or replace any component of it. Every constructor therefore
//! establishes:
//!
//! - the base is resolved and proven trusted: on Unix it is canonicalised and
//!   every ancestor is a real directory owned by the effective user or root,
//!   writable by no one else unless sticky; elsewhere, where the standard
//!   library offers no owner-only creation, it must resolve inside the current
//!   user's profile directory, which the OS keeps private to that user;
//! - entries are created under the resolved base, never the given path, so a
//!   link on the given path re-pointed after the check cannot redirect them;
//! - the private directory name carries 128 bits of OS CSPRNG entropy (an
//!   unavailable CSPRNG fails the creation, never weakens the name); it is
//!   created exclusively (mode 0700), a collision retries with a fresh name a
//!   bounded number of times, and it is re-verified with `symlink_metadata`: a
//!   real directory, owned by the effective user, no group/other permission bits;
//! - a scratch file is created inside such a directory with `O_EXCL` +
//!   `O_NOFOLLOW` + mode 0600, and its handle is verified with `fstat`; read it
//!   back through the retained handle, never by re-opening the name.
//!
//! A check that fails refuses with [`io::ErrorKind::PermissionDenied`] carrying
//! a [`ScratchError`] or a [`ScratchRootRefusal`]; nothing is created under an
//! untrusted base and nothing is written through a planted link.

/// The sandbox's host hooks for the shared scratch implementation.
mod scratch_host {
    use super::scratch_core::EntropyUnavailable;

    pub use crate::home::HomeDir;

    /// The variable naming the current user's profile directory on Windows.
    pub const PROFILE_VAR: &str = crate::home::WINDOWS_HOME_VAR;

    /// Fill `buf` from the OS CSPRNG.
    ///
    /// # Errors
    /// [`EntropyUnavailable`] when the OS random source cannot be read.
    pub fn fill_entropy(buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        getrandom::fill(buf).map_err(|e| EntropyUnavailable {
            detail: e.to_string(),
        })
    }

    /// The current user's profile directory, which off Unix must contain every scratch base.
    #[cfg(not(unix))]
    #[must_use]
    pub fn profile_dir() -> Option<HomeDir> {
        crate::home::home_dir().ok()
    }
}

/// The runtime's scratch primitive, spliced in verbatim.
///
/// The one source lives in the runtime tree because the runtime is vendored
/// into emitted apps and cannot depend on the compiler.
mod scratch_core {
    include!("../../../runtime/rust/src/scratch_core.rs");
}

pub use scratch_core::*;

// The runtime's temp-root names are the names `ipe_env` refuses: the two lists
// cannot drift without failing this build.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); it fails the build if the runtime's temp-root names drift from the names `ipe_env` refuses [ledger #boundary]
const _: () = assert!(names_eq(&TEMP_ROOT_NAMES, &ipe_env::TEMP_ROOT_NAMES));

/// Whether two name lists are equal, element by element.
const fn names_eq(a: &[&str], b: &[&str]) -> bool {
    match (a, b) {
        ([], []) => true,
        ([x, a @ ..], [y, b @ ..]) => bytes_eq(x.as_bytes(), y.as_bytes()) && names_eq(a, b),
        ([], [_, ..]) | ([_, ..], []) => false,
    }
}

/// Whether two byte strings are equal.
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    match (a, b) {
        ([], []) => true,
        ([x, a @ ..], [y, b @ ..]) => *x == *y && bytes_eq(a, b),
        ([], [_, ..]) | ([_, ..], []) => false,
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::ScratchDir;
    use std::io;
    use std::path::Path;

    /// A base outside the user's profile is refused before anything is created.
    #[cfg(windows)]
    #[test]
    fn windows_base_outside_profile_is_refused() {
        let system_root = ipe_env::var_os("SystemRoot");
        assert!(system_root.is_some(), "SystemRoot must be set on Windows");
        let Some(system_root) = system_root else {
            return;
        };
        let refused = ScratchDir::new_under(Path::new(&system_root), "ipe-test");
        assert_eq!(
            refused.map(drop).map_err(|e| e.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
    }

    /// A missing base outside the user's profile is refused without creating
    /// any of its ancestors.
    #[cfg(windows)]
    #[test]
    fn windows_missing_base_outside_profile_creates_nothing() {
        let system_root = ipe_env::var_os("SystemRoot");
        assert!(system_root.is_some(), "SystemRoot must be set on Windows");
        let Some(system_root) = system_root else {
            return;
        };
        let missing =
            Path::new(&system_root).join(format!("ipe-missing-scratch-{}", std::process::id()));
        let refused = ScratchDir::new_under(&missing.join("inner"), "ipe-test");
        assert_eq!(
            refused.map(drop).map_err(|e| e.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
        assert!(!missing.exists(), "a refused base must not be created");
    }
}

#[cfg(test)]
mod temp_root_key_tests {
    use std::ffi::OsStr;

    /// The runtime's temp-root spelling fold and `ipe_env`'s answer alike for
    /// every spelling, and each answer is the pinned one: case variants,
    /// non-ASCII case mappings onto a name, and near misses.
    #[test]
    fn the_runtime_and_env_folds_agree() {
        let cases: [(&str, bool); 16] = [
            ("TMPDIR", true),
            ("tmpdir", true),
            ("TmpDir", true),
            ("TMP", true),
            ("Tmp", true),
            ("TEMP", true),
            ("temp", true),
            ("tmpd\u{131}r", true),
            ("TMPDIRX", false),
            ("TMPDIR_", false),
            ("", false),
            ("TM", false),
            ("IPE_TMP", false),
            ("TEMPLATE", false),
            ("\u{ff34}\u{ff2d}\u{ff30}", false),
            (" TMP", false),
        ];
        for (key, refused) in cases {
            assert_eq!(
                super::is_temp_root_key(key),
                refused,
                "runtime fold: {key:?}"
            );
            assert_eq!(
                ipe_env::is_temp_root_key(OsStr::new(key)),
                refused,
                "ipe_env fold: {key:?}"
            );
        }
    }
}
