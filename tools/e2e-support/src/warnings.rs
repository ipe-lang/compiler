//! The emitted-build warning refusal.
//!
//! An emitted build that prints a `warning` compiler message from the runtime
//! crate or from the app crate fails the SEAL: a user never sees a warning from
//! code they did not write. The judge reads cargo's `--message-format=json`
//! stream, so the verdict rests on cargo's own attribution of each message to
//! a package, never on matching rendered text. Cargo caps the lints of
//! registry dependencies, so only path packages can report a warning; any
//! warning the judge cannot attribute is refused rather than admitted.

use std::fmt;

/// The runtime crate's package name, as cargo reports it in a package id.
pub const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";

/// One warning cargo reported for a package the SEAL covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmittedWarning {
    /// The package cargo attributed the warning to.
    pub package: String,
    /// The warning as rustc rendered it.
    pub rendered: String,
}

/// Why an emitted build's JSON stream was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WarningRefusal {
    /// The runtime or the app crate printed at least one warning.
    Warnings(Vec<EmittedWarning>),
    /// A warning carried no package id the judge can read.
    Unattributable {
        /// The raw JSON record.
        line: String,
    },
    /// A non-empty stdout line was not a JSON record.
    Malformed {
        /// The raw stdout line.
        line: String,
    },
    /// The stream carried no artifact for the app crate, so a judge keyed on
    /// that package name would have admitted every app warning.
    AppNotBuilt {
        /// The app package name the judge was keyed on.
        package: String,
    },
}

impl fmt::Display for WarningRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warnings(warnings) => {
                writeln!(
                    f,
                    "the emitted build printed {} warning(s) from the runtime or the app crate; \
                     fix each at its source",
                    warnings.len()
                )?;
                for warning in warnings {
                    writeln!(f, "--- {} ---\n{}", warning.package, warning.rendered)?;
                }
                Ok(())
            }
            Self::Unattributable { line } => {
                write!(
                    f,
                    "cargo reported a warning with no readable package id: {line}"
                )
            }
            Self::Malformed { line } => {
                write!(
                    f,
                    "cargo's JSON stream carried a line that is not JSON: {line}"
                )
            }
            Self::AppNotBuilt { package } => {
                write!(
                    f,
                    "cargo's JSON stream reported no artifact for the app package `{package}`"
                )
            }
        }
    }
}

/// Refuse every `warning` compiler message cargo attributed to the runtime
/// crate or to `app_package` in a `--message-format=json` stdout stream.
///
/// # Errors
///
/// [`WarningRefusal::Warnings`] lists every covered warning;
/// [`WarningRefusal::Unattributable`] and [`WarningRefusal::Malformed`] fail
/// closed on a record the judge cannot read; [`WarningRefusal::AppNotBuilt`]
/// fails closed when no `compiler-artifact` record names `app_package`, so a
/// mis-keyed app name cannot leave the app crate unjudged.
pub fn refuse_owned_warnings(json_stdout: &str, app_package: &str) -> Result<(), WarningRefusal> {
    let mut found = Vec::new();
    let mut app_built = false;
    for line in json_stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            return Err(WarningRefusal::Malformed {
                line: trimmed.to_owned(),
            });
        };
        match value.get("reason").and_then(serde_json::Value::as_str) {
            Some("compiler-message") => {}
            Some("compiler-artifact") => {
                app_built |= value
                    .get("package_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(package_name)
                    == Some(app_package);
                continue;
            }
            _ => continue,
        }
        let message = value.get("message");
        if message
            .and_then(|m| m.get("level"))
            .and_then(serde_json::Value::as_str)
            != Some("warning")
        {
            continue;
        }
        let Some(package) = value
            .get("package_id")
            .and_then(serde_json::Value::as_str)
            .and_then(package_name)
        else {
            return Err(WarningRefusal::Unattributable {
                line: trimmed.to_owned(),
            });
        };
        if package != RUNTIME_PACKAGE && package != app_package {
            continue;
        }
        let rendered = message
            .and_then(|m| m.get("rendered").or_else(|| m.get("message")))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        found.push(EmittedWarning {
            package: package.to_owned(),
            rendered,
        });
    }
    match (found.is_empty(), app_built) {
        (false, _) => Err(WarningRefusal::Warnings(found)),
        (true, true) => Ok(()),
        (true, false) => Err(WarningRefusal::AppNotBuilt {
            package: app_package.to_owned(),
        }),
    }
}

/// The package name inside a cargo package id, in either of cargo's formats.
///
/// The spec format is `<source-url>#<name>@<version>`, or `<source-url>#<version>`
/// when the name equals the URL's last path segment. The legacy format is
/// `<name> <version> (<source-url>)`.
fn package_name(id: &str) -> Option<&str> {
    let name = match id.split_once('#') {
        Some((url, fragment)) => fragment
            .split_once('@')
            .map_or_else(|| last_path_segment(url), |(name, _version)| Some(name))?,
        None => id.split_whitespace().next()?,
    };
    (!name.is_empty()).then_some(name)
}

/// The last path segment of a package-id source URL, ignoring its query.
fn last_path_segment(url: &str) -> Option<&str> {
    url.split('?')
        .next()?
        .trim_end_matches('/')
        .rsplit('/')
        .next()
}

#[cfg(test)]
mod tests {
    use super::{RUNTIME_PACKAGE, WarningRefusal, package_name, refuse_owned_warnings};

    const APP: &str = "ipe-app-e2e-probe";

    fn message(package_id: &str, level: &str) -> String {
        serde_json::json!({
            "reason": "compiler-message",
            "package_id": package_id,
            "message": { "level": level, "message": "function `dead` is never used",
                         "rendered": "warning: function `dead` is never used" },
        })
        .to_string()
    }

    /// The artifact record cargo prints once the app crate is built.
    fn app_artifact() -> String {
        serde_json::json!({
            "reason": "compiler-artifact",
            "package_id": format!("path+file:///scratch/out#{APP}@0.1.0"),
        })
        .to_string()
    }

    #[test]
    fn a_runtime_warning_is_refused() {
        let stream = message(
            "path+file:///repo/src/runtime/rust#ipe-runtime-rust@0.2.3",
            "warning",
        );
        let verdict = refuse_owned_warnings(&stream, APP);
        assert!(
            matches!(&verdict, Err(WarningRefusal::Warnings(w))
                if w.len() == 1 && w.iter().all(|w| w.package == RUNTIME_PACKAGE)),
            "{verdict:?}"
        );
    }

    #[test]
    fn an_app_warning_is_refused() {
        let stream = message(&format!("path+file:///scratch/out#{APP}@0.1.0"), "warning");
        assert!(matches!(
            refuse_owned_warnings(&stream, APP),
            Err(WarningRefusal::Warnings(_))
        ));
    }

    #[test]
    fn a_warning_from_another_package_is_admitted() {
        let stream = [
            message(
                "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                "warning",
            ),
            app_artifact(),
        ]
        .join("\n");
        assert_eq!(refuse_owned_warnings(&stream, APP), Ok(()));
    }

    #[test]
    fn errors_and_notes_are_not_warnings() {
        let stream = [
            message("path+file:///r#ipe-runtime-rust@0.2.3", "error"),
            message("path+file:///r#ipe-runtime-rust@0.2.3", "note"),
            app_artifact(),
            serde_json::json!({ "reason": "build-finished", "success": true }).to_string(),
        ]
        .join("\n");
        assert_eq!(refuse_owned_warnings(&stream, APP), Ok(()));
    }

    #[test]
    fn every_covered_warning_is_reported() {
        let stream = [
            message("path+file:///r#ipe-runtime-rust@0.2.3", "warning"),
            message(&format!("path+file:///o#{APP}@0.1.0"), "warning"),
        ]
        .join("\n");
        assert!(matches!(
            refuse_owned_warnings(&stream, APP),
            Err(WarningRefusal::Warnings(w)) if w.len() == 2
        ));
    }

    #[test]
    fn an_unattributable_warning_fails_closed() {
        let stream = serde_json::json!({
            "reason": "compiler-message",
            "message": { "level": "warning", "rendered": "warning: x" },
        })
        .to_string();
        assert!(matches!(
            refuse_owned_warnings(&stream, APP),
            Err(WarningRefusal::Unattributable { .. })
        ));
    }

    #[test]
    fn a_non_json_line_fails_closed() {
        assert!(matches!(
            refuse_owned_warnings("warning: not json", APP),
            Err(WarningRefusal::Malformed { .. })
        ));
    }

    #[test]
    fn a_stream_without_the_app_artifact_fails_closed() {
        let other = serde_json::json!({
            "reason": "compiler-artifact",
            "package_id": "path+file:///scratch/out#ipe-app@0.1.0",
        })
        .to_string();
        assert_eq!(
            refuse_owned_warnings(&other, APP),
            Err(WarningRefusal::AppNotBuilt {
                package: APP.to_owned()
            })
        );
        assert_eq!(
            refuse_owned_warnings("", APP),
            Err(WarningRefusal::AppNotBuilt {
                package: APP.to_owned()
            })
        );
    }

    #[test]
    fn package_ids_parse_in_every_cargo_format() {
        assert_eq!(
            package_name("path+file:///repo/src/runtime/rust#ipe-runtime-rust@0.2.3"),
            Some("ipe-runtime-rust")
        );
        assert_eq!(
            package_name("path+file:///scratch/ipe-runtime-rust#0.2.3"),
            Some("ipe-runtime-rust")
        );
        assert_eq!(
            package_name("ipe-runtime-rust 0.2.3 (path+file:///repo/src/runtime/rust)"),
            Some("ipe-runtime-rust")
        );
        assert_eq!(package_name(""), None);
        assert_eq!(package_name("#@1.0.0"), None);
    }
}
