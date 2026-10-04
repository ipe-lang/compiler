//! The invoking user's home directory, read from the environment in one place.
//!
//! Every compiler-side read of the platform home variable (`HOME`, or
//! `USERPROFILE` on Windows) goes through [`home_dir`]. The value is attacker-
//! reachable environment input that decides where caches, scratch roots, and
//! toolchain binds live, so it is parsed once here: an unset, empty,
//! relative, non-UTF-8, NUL-bearing, or `..`-bearing value names no directory,
//! and neither does a Windows device, verbatim, or UNC path. A relative home
//! would silently resolve against the working directory, redirecting writes to
//! wherever the process happens to run. `ipe_env` refuses every home name, so
//! this module's raw read is the only way a compiler-side crate reaches the
//! value.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The runtime's home-variable name and value parser, spliced in verbatim.
///
/// The one source lives in the runtime tree because the runtime is vendored
/// into emitted apps and cannot depend on the compiler.
mod home_core {
    include!("../../../runtime/rust/src/home_core.rs");
}

pub use home_core::{HomeDir, HomeRefusal, WINDOWS_HOME_VAR};

/// The invoking user's home directory, or why the environment names none.
///
/// The value is parsed by the shared [`HomeDir::try_parse`], the one
/// constructor every home reader uses, so this function makes no parsing
/// decision of its own. The refusal travels to the caller: an unset home
/// ([`HomeRefusal::Unset`]) and a set home this parser distrusts are different
/// facts, and a consumer that widens on absence must not widen on distrust.
///
/// # Errors
/// The [`HomeRefusal`] the platform home variable earns.
pub fn home_dir() -> Result<HomeDir, HomeRefusal> {
    HomeDir::try_parse(raw_home())
}

/// The platform home variable's value, accepted or refused, held only to be
/// erased from text.
///
/// A transcript must carry neither a trusted home nor a refused one, so the
/// redactor holds the raw value [`home_dir`] refuses to hand out as a path.
/// Redaction is its whole surface: no `AsRef<Path>`, `Into<PathBuf>`, `Deref`,
/// `Display` or `Debug` hands the value back, so no caller can build a
/// location from a value the parser distrusts.
pub struct HomeRedactor(String);

impl HomeRedactor {
    /// The current home value; `None` when it marks no path prefix (see
    /// [`redaction_text`]).
    #[must_use]
    pub fn current() -> Option<Self> {
        redaction_text(raw_home()).map(Self)
    }

    /// `input` with every occurrence of the home value replaced by
    /// `placeholder`.
    #[must_use]
    pub fn redact(&self, input: &str, placeholder: &str) -> String {
        input.replace(self.0.as_str(), placeholder)
    }

    /// The value's length in bytes, to order it among other redactions
    /// longest-first.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.0.len()
    }
}

/// The redactable text of a raw home value: an absolute path below a
/// filesystem root, rendered lossily.
///
/// The redactor replaces every occurrence of the text, so a value that is not
/// a path prefix would rewrite unrelated output: a relative value (`u`) every
/// matching word, a bare root (`/`) every separator.
fn redaction_text(raw: Option<OsString>) -> Option<String> {
    let text = raw?.to_string_lossy().into_owned();
    let path = Path::new(&text);
    (path.is_absolute() && path.parent().is_some()).then_some(text)
}

/// The platform home variable's raw value.
#[allow(clippy::disallowed_methods)] // the sole home read: parsed by `HomeDir::try_parse` or rendered for redaction
fn raw_home() -> Option<OsString> {
    std::env::var_os(home_core::HOME_VAR)
}

/// A tool-home variable (`CARGO_HOME`, `RUSTUP_HOME`) set to a relative path.
///
/// The tool honours a relative value against its working directory, so no
/// fixed directory can be derived from it: every consumer refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativeToolHome {
    /// The offending variable.
    pub var: &'static str,
}

impl std::fmt::Display for RelativeToolHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}` must be an absolute path", self.var)
    }
}

impl std::error::Error for RelativeToolHome {}

/// A tool home (`CARGO_HOME`, `RUSTUP_HOME`) proven absolute.
///
/// Either the variable's own absolute value or a literal tail joined beneath a
/// [`HomeDir`]. Only [`tool_home_from`] and [`ToolHome::under`] build one, so
/// no holder re-checks that the path is absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolHome(PathBuf);

impl ToolHome {
    /// The default tool home `<home>/<fallback>`, for a variable that is unset.
    #[must_use]
    pub fn under(home: &HomeDir, fallback: &'static str) -> Self {
        Self(home.join(fallback))
    }

    /// The verified path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The path `tail` names beneath this tool home.
    ///
    /// Only a literal tail is accepted, so no runtime-computed absolute value
    /// can stand in for the tool home.
    #[must_use]
    pub fn join(&self, tail: &'static str) -> PathBuf {
        self.0.join(tail)
    }
}

/// A tool home (`CARGO_HOME`, `RUSTUP_HOME`): `var` when set, else `<home>/<fallback>`.
///
/// `home` is the caller's one parse of the user home; a refused home (`None`)
/// gives no fallback, so the result is `None` exactly when `var` is unset and
/// no home is proven.
///
/// # Errors
/// [`RelativeToolHome`] when `var` is set, non-empty, and relative.
pub fn tool_home(
    var: &'static str,
    home: Option<&HomeDir>,
    fallback: &'static str,
) -> Result<Option<ToolHome>, RelativeToolHome> {
    tool_home_from(var, ipe_env::var_os(var), home, fallback)
}

/// Resolve a tool home from the raw variable value and the parsed home.
///
/// An empty value counts as unset.
///
/// # Errors
/// [`RelativeToolHome`] when `raw` is non-empty and relative.
pub fn tool_home_from(
    var: &'static str,
    raw: Option<OsString>,
    home: Option<&HomeDir>,
    fallback: &'static str,
) -> Result<Option<ToolHome>, RelativeToolHome> {
    raw.filter(|raw| !raw.is_empty()).map_or_else(
        || Ok(home.map(|home| ToolHome::under(home, fallback))),
        |raw| {
            let path = PathBuf::from(raw);
            if path.is_absolute() {
                Ok(Some(ToolHome(path)))
            } else {
                Err(RelativeToolHome { var })
            }
        },
    )
}

/// Test-only: `path` parsed as a home, for fixtures over a real directory.
#[cfg(test)]
#[allow(clippy::expect_used)] // test fixture: the path is absolute by construction
pub(crate) fn test_home(path: &Path) -> HomeDir {
    HomeDir::try_parse(Some(path.as_os_str().to_os_string())).expect("fixture home parses")
}

/// Test-only: `path` as a tool home, built through [`tool_home_from`].
#[cfg(test)]
#[allow(clippy::expect_used)] // test fixture: the path is absolute by construction
pub(crate) fn test_tool_home(path: &Path) -> ToolHome {
    tool_home_from(
        "CARGO_HOME",
        Some(path.as_os_str().to_os_string()),
        None,
        ".cargo",
    )
    .ok()
    .flatten()
    .expect("fixture tool home is absolute")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared table, two modules below `home` like the runtime's include.
    mod shared {
        use std::ffi::OsString;
        use std::path::PathBuf;

        // Shared with `ipe_runtime_rust::system`'s `home_dir_tests`: the same
        // rows drive both crates' home readers and the shared parser.
        include!("../../../runtime/rust/tests/data/home_cases.rs");

        #[test]
        fn every_home_parse_case_matches_the_shared_table() {
            for (raw, expected) in HOME_PARSE_CASES.iter().chain(HOME_PARSE_PLATFORM_CASES) {
                assert_eq!(
                    HomeDir::try_parse(raw.map(OsString::from))
                        .ok()
                        .map(|home| home.as_path().to_path_buf()),
                    expected.map(PathBuf::from),
                    "{raw:?}"
                );
            }
        }

        /// A non-UTF-8 raw value is refused even when byte-for-byte absolute.
        #[cfg(unix)]
        #[test]
        fn a_non_utf8_home_value_is_refused() {
            use std::os::unix::ffi::OsStrExt as _;
            let raw = std::ffi::OsStr::from_bytes(b"/home/\xff").to_os_string();
            assert_eq!(HomeDir::try_parse(Some(raw)), Err(HomeRefusal::NotUtf8));
        }
    }

    /// The shared home variable is `USERPROFILE` on Windows and `HOME` elsewhere.
    #[test]
    fn the_home_variable_is_the_platform_convention() {
        let expected = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        assert_eq!(home_core::HOME_VAR, expected);
        assert_eq!(WINDOWS_HOME_VAR, "USERPROFILE");
    }

    /// Every shared home name is one `ipe_env` refuses to read.
    #[test]
    fn every_shared_home_name_is_refused_by_ipe_env() {
        for name in [home_core::HOME_VAR, WINDOWS_HOME_VAR] {
            assert!(ipe_env::HOME_NAMES.contains(&name), "{name}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn a_tool_home_joins_under_a_parsed_home() {
        let home = HomeDir::try_parse(Some("/home/u".into())).expect("fixture home parses");
        assert_eq!(
            tool_home_from(
                "CARGO_HOME",
                Some("/opt/cargo".into()),
                Some(&home),
                ".cargo"
            )
            .map(|tool| tool.map(|tool| tool.as_path().to_path_buf())),
            Ok(Some(PathBuf::from("/opt/cargo")))
        );
        for raw in [None, Some(OsString::new())] {
            assert_eq!(
                tool_home_from("CARGO_HOME", raw, Some(&home), ".cargo")
                    .map(|tool| tool.map(|tool| tool.as_path().to_path_buf())),
                Ok(Some(PathBuf::from("/home/u/.cargo")))
            );
        }
        assert_eq!(tool_home_from("CARGO_HOME", None, None, ".cargo"), Ok(None));
    }

    /// A refused home is redacted when it marks a path prefix; a value that
    /// marks none (relative, bare root, empty, unset) is never redaction text.
    #[cfg(unix)]
    #[test]
    fn redaction_text_is_an_absolute_path_below_the_root() {
        use std::os::unix::ffi::OsStrExt as _;
        for (raw, expected) in [
            (Some("/home/u"), Some("/home/u")),
            (Some("/home/u/../v"), Some("/home/u/../v")),
            (Some("/"), None),
            (Some("//"), None),
            (Some(""), None),
            (Some("u"), None),
            (Some("home/u"), None),
            (None, None),
        ] {
            assert_eq!(
                redaction_text(raw.map(OsString::from)),
                expected.map(str::to_owned),
                "{raw:?}"
            );
        }
        let non_utf8 = std::ffi::OsStr::from_bytes(b"/home/\xff").to_os_string();
        assert_eq!(
            redaction_text(Some(non_utf8)),
            Some("/home/\u{fffd}".to_owned())
        );
        let refused = HomeRedactor("/home/u/../v".to_owned());
        assert_eq!(
            refused.redact("at /home/u/../v/src and /home/u", "<TMP>"),
            "at <TMP>/src and /home/u"
        );
        assert_eq!(refused.byte_len(), "/home/u/../v".len());
    }

    #[test]
    fn a_relative_tool_home_is_refused() {
        for raw in [".", "cargo", "./cargo", "../cargo", "~/.cargo"] {
            assert_eq!(
                tool_home_from("CARGO_HOME", Some(raw.into()), None, ".cargo"),
                Err(RelativeToolHome { var: "CARGO_HOME" }),
                "{raw:?}"
            );
        }
    }
}
