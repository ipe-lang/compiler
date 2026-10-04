//! Shared catalog + redaction for the CLI transcript goldens.
//!
//! Both the integration test (`tests/cli_transcripts.rs`) and the regeneration
//! tool (`tools/regen-cli-transcripts`) read this one module, so the set of
//! hermetic invocations, the redaction rule, the command classification, and the
//! golden envelope have a single source and cannot drift. The test asserts the
//! committed goldens match a redacted live run; the tool writes those goldens
//! from the same run.
//!
//! # Hermetic surface
//!
//! Only self-contained, deterministic commands are snapshotted (see
//! [`classify`]). Every command's `--help` page is snapshotted (help is a pure
//! render of the `help::COMMANDS` entry); a command whose body runs cargo, the
//! network, git, or a live login is [`Hermetic::Excluded`] from a body snapshot
//! and stays on the property-based checks.
//!
//! # Redaction
//!
//! CLI output embeds tokens that vary between runs, releases, and machines. A
//! raw snapshot would churn on every release. [`redact`] removes every such
//! token:
//!
//! * **`<VERSION>`** — the running `CARGO_PKG_VERSION` (help header + `version`).
//! * **`<TMP>`** — machine/checkout-specific absolute path prefixes (workspace
//!   root, OS temp dir, `$HOME`), supplied by the caller.
//! * **`<DUR>`** — any elapsed/duration measurement (`12ms`, `1.3s`, `900µs`).

use std::path::{Path, PathBuf};

/// One hermetic invocation to snapshot, beyond the per-command `--help` pages.
pub struct Invocation {
    /// The golden basename under `tests/golden/cli/` (no extension).
    pub golden: &'static str,
    /// Build the args after the binary name from the workspace root, or `None`
    /// to skip on a sparse checkout that lacks a referenced fixture.
    pub args: fn(&Path) -> Option<Vec<String>>,
}

/// The extra hermetic invocations: top-level help, group help, `version`, and
/// the deterministic command bodies over committed fixtures.
///
/// The per-command `--help` pages are enumerated separately from
/// [`help::command_names`].
pub const INVOCATIONS: &[Invocation] = &[
    Invocation {
        golden: "toplevel_help",
        args: |_root| Some(vec!["--help".to_owned()]),
    },
    Invocation {
        golden: "dev_group_help",
        args: |_root| Some(vec!["dev".to_owned(), "--help".to_owned()]),
    },
    Invocation {
        golden: "version",
        args: |_root| Some(vec!["version".to_owned()]),
    },
    Invocation {
        golden: "version_plain",
        args: |_root| Some(vec!["version".to_owned(), "--plain".to_owned()]),
    },
    Invocation {
        golden: "doc_explain_code",
        // A pure diagnostic-code lookup: no project, no cargo, no network.
        args: |_root| Some(vec!["doc".to_owned(), "IPE-L0131".to_owned()]),
    },
    Invocation {
        golden: "capabilities_http",
        // Inference over a committed fixture; `--plain` is flush-left and carries
        // no version banner. Skipped on a sparse checkout lacking the fixture.
        args: |root| {
            let fixture = root.join("src/ipe-cli/tests/fixtures/capabilities/uses_http.ipe");
            fixture.is_file().then(|| {
                vec![
                    "capabilities".to_owned(),
                    fixture.to_string_lossy().into_owned(),
                    "--plain".to_owned(),
                ]
            })
        },
    },
];

/// Whether a `help::COMMANDS` name is hermetic (snapshottable body) or excluded.
pub enum Hermetic {
    /// The command body is deterministic; snapshot its transcript (in addition
    /// to its help page).
    Snapshot,
    /// The command runs cargo / network / git / a live login, so its body's
    /// output is flaky and is NOT snapshotted; the reason records why. Its
    /// `--help` page is still snapshotted (help is a pure render).
    Excluded(&'static str),
}

/// Classify every advertised command. A new `help::COMMANDS` entry must be added
/// here or the completeness test reddens — so a new command cannot escape a
/// transcript decision.
#[must_use]
pub fn classify(name: &str) -> Hermetic {
    match name {
        // Deterministic, self-contained command bodies. `version`,
        // `capabilities`, and `doc` are each driven by an [`INVOCATIONS`] entry;
        // `diff` needs two package trees and is body-driven in diff_cli.rs, but is
        // `Snapshot` here so its `--help` page acquires a golden like the rest.
        "version" | "capabilities" | "doc" | "diff" => Hermetic::Snapshot,

        // Cargo / build / run / execute — heavy, environment-dependent output.
        "build" | "run" | "release" | "test" | "verify" | "exec" | "watch" => {
            Hermetic::Excluded("runs cargo / builds / executes — flaky transcript")
        }

        // Network / registry / login — reaches a remote party.
        "package" | "login" | "upgrade" | "add" | "remove" => {
            Hermetic::Excluded("reaches the network / registry — flaky transcript")
        }

        // Project-tree mutators / environment probes — output depends on a
        // project or the host toolchain. `type-check` reads and compiles a
        // project tree, so its diagnostics/paths are environment-dependent.
        "type-check" | "lint" | "fmt" | "clean" | "fix" | "eject" | "rust" | "health" => {
            Hermetic::Excluded("depends on a project tree / host toolchain — flaky transcript")
        }

        // Scaffolds a new project on disk; its body echoes the created path.
        "init" => Hermetic::Excluded("scaffolds a project on disk — path-dependent transcript"),

        // The language server speaks LSP over stdio, not a human transcript.
        "lsp" => Hermetic::Excluded("speaks LSP over stdio — no human transcript"),

        // An unclassified command: fail closed. The completeness test turns this
        // into a hard failure naming the command, so a new one is forced in.
        _ => Hermetic::Excluded("UNCLASSIFIED — add this command to classify()"),
    }
}

/// The sentinel a completeness check greps for to detect an unclassified command.
pub const UNCLASSIFIED_SENTINEL: &str = "UNCLASSIFIED";

/// One absolute path prefix to redact to `<TMP>`.
///
/// The OS temp root and the home value stay behind their redaction-only
/// wrappers: this list never holds either as text a caller could turn back
/// into a path.
enum VolatilePrefix {
    Text(String),
    TempRoot(ipe_sandbox::scratch::TempRootRedactor),
    Home(ipe_sandbox::home::HomeRedactor),
}

impl VolatilePrefix {
    const fn byte_len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::TempRoot(root) => root.byte_len(),
            Self::Home(home) => home.byte_len(),
        }
    }

    fn redact(&self, input: &str) -> String {
        match self {
            Self::Text(text) if text.is_empty() => input.to_owned(),
            Self::Text(text) => input.replace(text.as_str(), "<TMP>"),
            Self::TempRoot(root) => root.redact(input, "<TMP>"),
            Self::Home(home) => home.redact(input, "<TMP>"),
        }
    }
}

/// The absolute path prefixes to redact to `<TMP>`, longest first so a nested
/// prefix does not shadow a longer one.
///
/// Derived from the workspace root, the OS temp dir, and `$HOME` — the
/// machine/checkout-specific prefixes any path in the hermetic surface can carry.
fn volatile_path_prefixes(repo_root: &Path) -> Vec<VolatilePrefix> {
    let mut prefixes: Vec<VolatilePrefix> = Vec::new();
    if let Ok(canon) = repo_root.canonicalize() {
        prefixes.push(VolatilePrefix::Text(canon.to_string_lossy().into_owned()));
    }
    prefixes.push(VolatilePrefix::Text(
        repo_root.to_string_lossy().into_owned(),
    ));
    if let Some(temp_root) = ipe_sandbox::scratch::TempRootRedactor::current() {
        prefixes.push(VolatilePrefix::TempRoot(temp_root));
    }
    // A refused home is redacted too: the transcript carries the raw value
    // whether or not the parser trusts it as a directory.
    if let Some(home) = ipe_sandbox::home::HomeRedactor::current() {
        prefixes.push(VolatilePrefix::Home(home));
    }
    prefixes.sort_by_key(|p| std::cmp::Reverse(p.byte_len()));
    prefixes
}

/// The shared redactor: replace every volatile token with a stable placeholder.
///
/// Order matters — absolute paths run before the version token so a path that
/// contains the version string is redacted as a path first, and durations run
/// before the version so a version-shaped duration is not mis-tagged.
#[must_use]
pub fn redact(input: &str, repo_root: &Path) -> String {
    let mut s = input.to_owned();

    for prefix in volatile_path_prefixes(repo_root) {
        s = prefix.redact(&s);
    }

    s = redact_durations(&s);

    let version = env!("CARGO_PKG_VERSION");
    s = s.replace(version, "<VERSION>");

    s
}

/// Replace every `<number><time-unit>` run with `<DUR>`. Scanned char-by-char so
/// the catalog pulls in no regex crate. Units: `ms`, `µs`, `us`, `ns`, `s`, `m`,
/// `h`.
fn redact_durations(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        // A duration begins at a digit whose previous char is not alphanumeric,
        // so an identifier's embedded digits are never clobbered.
        let prev_alnum = i > 0 && chars.get(i - 1).is_some_and(|c| c.is_alphanumeric());
        if !prev_alnum
            && chars.get(i).is_some_and(char::is_ascii_digit)
            && let Some(end) = duration_run(&chars, i)
        {
            out.push_str("<DUR>");
            i = end;
            continue;
        }
        if let Some(c) = chars.get(i) {
            out.push(*c);
        }
        i += 1;
    }
    out
}

/// If a duration token (`<digits>[.<digits>]<unit>`) starts at `start`, return
/// the index just past it; else `None`.
fn duration_run(chars: &[char], start: usize) -> Option<usize> {
    let mut j = start;
    while chars.get(j).is_some_and(char::is_ascii_digit) {
        j += 1;
    }
    if chars.get(j) == Some(&'.') {
        j += 1;
        let mut saw = false;
        while chars.get(j).is_some_and(char::is_ascii_digit) {
            j += 1;
            saw = true;
        }
        if !saw {
            return None; // a trailing dot with no fraction is not a duration
        }
    }
    for unit in ["ms", "µs", "us", "ns", "s", "m", "h"] {
        let unit_chars: Vec<char> = unit.chars().collect();
        if chars
            .get(j..)
            .is_some_and(|rest| rest.starts_with(unit_chars.as_slice()))
        {
            let after = j + unit_chars.len();
            let bleeds = chars.get(after).is_some_and(|c| c.is_alphanumeric());
            if !bleeds {
                return Some(after);
            }
        }
    }
    None
}

/// The golden envelope for a transcript: the exit code on a header line, a `---`
/// separator, then the redacted stdout.
///
/// Identical shape on both the test's comparison side and the tool's write side,
/// so a golden written by the tool is exactly what the test reads back.
#[must_use]
pub fn golden_envelope(exit_code: Option<i32>, redacted_stdout: &str) -> String {
    let code = exit_code.map_or_else(|| "signal".to_owned(), |c| c.to_string());
    format!("exit: {code}\n---\n{redacted_stdout}")
}

/// The committed golden directory for CLI transcripts, under the workspace root.
#[must_use]
pub fn golden_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("src/ipe-cli/tests/golden/cli")
}

/// The per-command `--help` golden basename (`help_<command>`).
#[must_use]
pub fn help_golden_name(command: &str) -> String {
    format!("help_{command}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::help;

    #[test]
    fn redacts_the_running_version() {
        let v = env!("CARGO_PKG_VERSION");
        let out = redact(
            &format!("Ipê language - v{v} - url"),
            Path::new("/nonexistent"),
        );
        assert!(out.contains("<VERSION>"), "version must be redacted: {out}");
        assert!(!out.contains(v), "raw version must not survive: {out}");
    }

    #[test]
    fn redacts_durations_but_not_identifiers() {
        let out = redact("built in 1.3s and 42ms", Path::new("/nonexistent"));
        assert_eq!(out, "built in <DUR> and <DUR>");
        // A version-like identifier with embedded digits is left alone.
        let out2 = redact("crate_v2 has 3 items", Path::new("/nonexistent"));
        assert!(out2.contains("crate_v2"), "identifier must survive: {out2}");
    }

    #[test]
    fn redacts_absolute_path_prefixes() {
        let root = ipe_test_temp::temp_root();
        let sample = format!("{}/proj/Main.ipe", root.display());
        let out = redact(&sample, &root);
        assert!(
            out.starts_with("<TMP>"),
            "path prefix must be redacted: {out}"
        );
    }

    /// The classification must cover exactly the `help::COMMANDS` set — no
    /// unclassified fallback. This is the relation that forces a new command in.
    #[test]
    fn every_command_is_classified() {
        for name in help::command_names() {
            if let Hermetic::Excluded(reason) = classify(name) {
                assert!(
                    !reason.contains(UNCLASSIFIED_SENTINEL),
                    "command `{name}` is not classified in cli_transcript::classify — \
                     add it (Snapshot for a deterministic body, or Excluded with a reason)",
                );
                assert!(
                    !reason.trim().is_empty(),
                    "excluded command `{name}` must carry a non-empty reason",
                );
            }
        }
    }
}
