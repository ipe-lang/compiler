//! Directory discovery from the environment, absolute paths only.
//!
//! Every per-user location the CLI derives from the environment (`HOME`,
//! `XDG_*_HOME`, `CARGO_HOME`, `RUSTUP_HOME`, explicit `IPE_*` overrides) is
//! resolved here. A value that is unset, empty, or relative names no directory:
//! a relative path would silently resolve against whatever the current working
//! directory happens to be, so it is never used. Ambient variables (`HOME`,
//! `XDG_*`) fall through to the next candidate, as the XDG spec requires
//! ([`ambient_home`]); an explicit override or tool home that is set but not
//! absolute is refused outright ([`explicit_override`], [`tool_home`]), never
//! silently replaced by the default.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::CliError;

pub use ipe_sandbox::home::{HomeDir, HomeRefusal, ToolHome};

/// The directory a raw environment value names, when it is absolute.
#[must_use]
pub fn absolute(raw: Option<OsString>) -> Option<PathBuf> {
    raw.map(PathBuf::from).filter(|p| p.is_absolute())
}

/// The invoking user's home directory, or why the environment names none.
///
/// Delegates to the one compiler-side home accessor, [`ipe_sandbox::home::home_dir`].
/// A consumer that falls through on a missing home takes `.ok()`; one that
/// widens on absence matches [`HomeRefusal::Unset`] alone.
///
/// # Errors
/// The [`HomeRefusal`] the platform home variable earns.
pub fn home() -> Result<HomeDir, HomeRefusal> {
    ipe_sandbox::home::home_dir()
}

/// An ambient base directory: `var` when absolute, else `<home>/<fallback>`.
///
/// For XDG-style variables, whose spec says a relative value is ignored; a
/// tool override is resolved by [`tool_home`] instead.
#[must_use]
pub fn ambient_home(var: &str, fallback: &'static str) -> Option<PathBuf> {
    ambient_home_from(ipe_env::var_os(var), home().ok().as_ref(), fallback)
}

/// Resolve an ambient base directory from the raw variable value and the home.
#[must_use]
pub fn ambient_home_from(
    raw: Option<OsString>,
    home: Option<&HomeDir>,
    fallback: &'static str,
) -> Option<PathBuf> {
    absolute(raw).or_else(|| home.map(|h| h.join(fallback)))
}

/// A tool home (`CARGO_HOME`, `RUSTUP_HOME`): `var` when set, else `<home>/<fallback>`.
///
/// The caller reads the home once and hands it to every tool home it derives,
/// so one decision never sees two different homes.
///
/// The tool itself honours a relative value against its working directory, so
/// substituting the default would make ipe and the tool disagree on the
/// directory; a set, non-empty, relative value is refused instead. An empty
/// value counts as unset, as the tool treats it.
///
/// Delegates to the one tool-home reader, [`ipe_sandbox::home::tool_home`].
///
/// # Errors
/// [`CliError::EnvDirNotAbsolute`] when `var` is set, non-empty, and relative.
pub fn tool_home(
    var: &'static str,
    home: Option<&HomeDir>,
    fallback: &'static str,
) -> Result<Option<ToolHome>, CliError> {
    ipe_sandbox::home::tool_home(var, home, fallback)
        .map_err(|relative| CliError::EnvDirNotAbsolute { var: relative.var })
}

/// Resolve a tool home from the raw variable value and the resolved home.
///
/// Delegates to the one tool-home parser, [`ipe_sandbox::home::tool_home_from`].
///
/// # Errors
/// [`CliError::EnvDirNotAbsolute`] when `raw` is non-empty and relative.
pub fn tool_home_from(
    var: &'static str,
    raw: Option<OsString>,
    home: Option<&HomeDir>,
    fallback: &'static str,
) -> Result<Option<ToolHome>, CliError> {
    ipe_sandbox::home::tool_home_from(var, raw, home, fallback)
        .map_err(|relative| CliError::EnvDirNotAbsolute { var: relative.var })
}

/// An explicit directory override: `None` when unset, the path when absolute.
///
/// # Errors
/// [`CliError::EnvDirNotAbsolute`] when the variable is set (empty included) but
/// is not an absolute path.
pub fn explicit_override(
    var: &'static str,
    raw: Option<OsString>,
) -> Result<Option<PathBuf>, CliError> {
    raw.map_or(Ok(None), |raw| {
        absolute(Some(raw))
            .map(Some)
            .ok_or(CliError::EnvDirNotAbsolute { var })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A parsed home over `path`.
    fn parsed(path: &str) -> HomeDir {
        HomeDir::try_parse(Some(path.into())).expect("an absolute test home")
    }

    #[test]
    fn absolute_accepts_only_an_absolute_path() {
        assert_eq!(
            absolute(Some("/abs/dir".into())),
            Some(PathBuf::from("/abs/dir"))
        );
        assert_eq!(absolute(Some("relative/dir".into())), None);
        assert_eq!(absolute(Some("./dir".into())), None);
        assert_eq!(absolute(Some(OsString::new())), None);
        assert_eq!(absolute(None), None);
    }

    #[test]
    #[cfg(not(windows))]
    fn ambient_home_prefers_an_absolute_variable() {
        let got = ambient_home_from(
            Some("/xdg/config".into()),
            Some(&parsed("/home/u")),
            ".config",
        );
        assert_eq!(got, Some(PathBuf::from("/xdg/config")));
    }

    #[test]
    #[cfg(not(windows))]
    fn ambient_home_ignores_a_relative_variable() {
        for raw in ["", "config", "./config"] {
            let got = ambient_home_from(Some(raw.into()), Some(&parsed("/home/u")), ".config");
            assert_eq!(got, Some(PathBuf::from("/home/u/.config")), "{raw:?}");
            assert_eq!(
                ambient_home_from(Some(raw.into()), None, ".config"),
                None,
                "{raw:?}"
            );
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn tool_home_uses_an_absolute_variable() {
        let got = tool_home_from(
            "CARGO_HOME",
            Some("/opt/cargo".into()),
            Some(&parsed("/home/u")),
            ".cargo",
        );
        assert!(matches!(got, Ok(Some(p)) if p.as_path() == std::path::Path::new("/opt/cargo")));
    }

    #[test]
    #[cfg(not(windows))]
    fn tool_home_unset_or_empty_defaults_under_the_home() {
        for raw in [None, Some("")] {
            let got = tool_home_from(
                "CARGO_HOME",
                raw.map(OsString::from),
                Some(&parsed("/home/u")),
                ".cargo",
            );
            assert!(
                matches!(&got, Ok(Some(p)) if p.as_path() == std::path::Path::new("/home/u/.cargo")),
                "{raw:?}"
            );
            let got = tool_home_from("CARGO_HOME", raw.map(OsString::from), None, ".cargo");
            assert!(matches!(got, Ok(None)), "{raw:?}");
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn tool_home_refuses_a_relative_variable() {
        for raw in ["cargo", "./cargo", "../cargo"] {
            let got = tool_home_from(
                "CARGO_HOME",
                Some(raw.into()),
                Some(&parsed("/home/u")),
                ".cargo",
            );
            assert!(
                matches!(got, Err(CliError::EnvDirNotAbsolute { var: "CARGO_HOME" })),
                "`{raw}` must be refused, never replaced by the home default"
            );
        }
    }

    #[test]
    fn tool_home_without_a_home_names_no_default() {
        let got = tool_home_from("RUSTUP_HOME", None, None, ".rustup");
        assert!(matches!(got, Ok(None)));
    }

    #[test]
    fn explicit_override_unset_defers_to_the_default() {
        assert!(matches!(explicit_override("IPE_INDEX_DIR", None), Ok(None)));
    }

    #[test]
    fn explicit_override_absolute_is_used() {
        let got = explicit_override("IPE_INDEX_DIR", Some("/srv/index".into()));
        assert!(matches!(got, Ok(Some(p)) if p == std::path::Path::new("/srv/index")));
    }

    #[test]
    fn explicit_override_relative_or_empty_is_refused() {
        for raw in ["index", "./index", "../index", ""] {
            let got = explicit_override("IPE_INDEX_DIR", Some(raw.into()));
            assert!(
                matches!(
                    got,
                    Err(CliError::EnvDirNotAbsolute {
                        var: "IPE_INDEX_DIR"
                    })
                ),
                "`{raw}` must be refused"
            );
        }
    }

    #[test]
    fn refusal_names_the_variable() {
        let got = explicit_override("IPE_HOME", Some("rel".into()));
        assert!(matches!(got, Err(CliError::EnvDirNotAbsolute { .. })));
        let Err(err) = got else { return };
        assert!(
            err.to_string()
                .starts_with("IPE_HOME is set but is not an absolute path")
        );
        assert_eq!(err.machine_kind(), "env-dir-not-absolute");
    }
}
