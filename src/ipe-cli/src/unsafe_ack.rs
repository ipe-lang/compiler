//! The build-time acknowledgment for `Ipe.<M>.Unsafe` escape-hatch imports.
//!
//! Ipê already *discloses* the `unsafe` capability (a program that imports an
//! `Ipe.<M>.Unsafe` submodule flips [`Capability::Unsafe`], visible in
//! `ipe capabilities`). Disclosure serves the auditor of a dependency; this gate
//! serves the author exposing *their own* program. When user code reaches for a
//! disclosed hatch, `ipe dev build`/`ipe dev run` surface the risk (which module, what
//! risk) and require consent before proceeding.
//!
//! The stance is non-patronizing: the safe path (no `.Unsafe` import) is silent —
//! no warning, no prompt, no flag. The acknowledgment fires *only* on a real,
//! disclosed exposure.
//!
//! Consent has three forms, in precedence order:
//! - the one-off `--accept-risks` flag,
//! - the durable `[capabilities] accept = ["unsafe"]` manifest token,
//! - an interactive `y` at a real terminal prompt.
//!
//! Non-interactive is the security-critical case: a CI build MUST NEVER hang on a
//! stdin prompt. Without pre-acceptance a non-TTY build fails closed with
//! `IPE-S0001` and the remedy; it never blocks.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ipe_diagnostics::{ConsentError, Diagnostic as SharedDiag};
use std::io::{IsTerminal, Write};

use ipe_ir::Capability;

use crate::CliError;

/// Extract the distinct `Ipe.<M>.Unsafe` module paths named by `import` lines
/// across the given source texts, sorted for a stable report.
///
/// A dotted import whose FIRST segment is `Ipe` and whose LAST segment is
/// `Unsafe`, with at least one module segment between (`Ipe.Html.Unsafe`,
/// `Ipe.Db.Unsafe`), is the escape-hatch signal — the SAME segment rule canon's
/// `imports_an_unsafe_submodule` keys the `unsafe` capability off. This is a
/// human-facing *detail* (the `via …` breakdown); the authoritative "does it use
/// unsafe" answer is the already-computed capability set, not this scan.
///
/// Text-level (not a full parse) on purpose: it reads only the leading
/// `import <path>` token of each line, which is stable across the surface syntax
/// and cannot misclassify a non-import occurrence of the word `Unsafe`.
#[must_use]
pub fn unsafe_modules_in_sources<'a>(sources: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for src in sources {
        for line in src.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed.strip_prefix("import ") else {
                continue;
            };
            // The module path is the first whitespace-delimited token after
            // `import` (before any `as` / `exposing`).
            let Some(path) = rest.split_whitespace().next() else {
                continue;
            };
            if is_unsafe_module_path(path) {
                found.insert(path.to_owned());
            }
        }
    }
    found.into_iter().collect()
}

/// Whether a dotted module path names an `Ipe.<M>.Unsafe` escape-hatch submodule:
/// first segment `Ipe`, last segment `Unsafe`, at least three segments total.
fn is_unsafe_module_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    matches!(
        segments.as_slice(),
        [first, _, .., last] if *first == "Ipe" && *last == "Unsafe"
    )
}

/// Render the acknowledgment message: which modules, what risk, how to accept.
///
/// `via` is the sorted `.Unsafe` module list from [`unsafe_modules_in_sources`].
/// When it is empty (the capability fired but the scan found no import line — a
/// belt-and-suspenders fallback) the message still names the generic risk and the
/// remedy, so the gate is never silently content-free.
#[must_use]
fn acknowledgment_text(via: &[String]) -> String {
    let mut out = String::new();
    out.push_str("this program imports an unsafe escape hatch\n");
    if via.is_empty() {
        out.push_str(
            "  = an `Ipe.<M>.Unsafe` submodule builds a security-tier value by assertion, \n\
             \x20   bypassing the parse the safe path runs. Untrusted input reaching such a \n\
             \x20   sink is a real vulnerability (XSS / SQL injection / secret leak).\n",
        );
    } else {
        for m in via {
            use std::fmt::Write as _;
            let _ = writeln!(out, "  = imports {m} — {}", risk_of(m));
        }
    }
    out.push_str(
        "  = the safe path is the ordinary, escaped API (e.g. Ipe.Html.text, \n\
         \x20   Ipe.Db.Sql column binds); reach for `.Unsafe` only for genuinely trusted input.\n",
    );
    out
}

/// A one-line, human-readable risk for a known `.Unsafe` module, falling back to
/// a generic parse-bypass description for any not-yet-enumerated hatch (the
/// vocabulary is open across future `.Unsafe` submodules; a missing entry must
/// still disclose *a* risk rather than nothing).
fn risk_of(module: &str) -> &'static str {
    match module {
        "Ipe.Html.Unsafe" => {
            "builds HTML from an unchecked String, bypassing the XSS escaper (cross-site scripting)"
        }
        "Ipe.Db.Unsafe" => {
            "builds SQL from an unchecked String, bypassing parameterisation (SQL injection)"
        }
        "Ipe.Secret.Unsafe" => "reveals a Secret's raw value outside a scoped use (secret leakage)",
        _ => "mints a security-tier value by assertion instead of by parse (a parse-bypass sink)",
    }
}

/// The remedy line every refusal / prompt shares.
const fn remedy_line() -> &'static str {
    "  = re-run with --accept-risks to take responsibility and proceed, or add \n\
     \x20   `accept = [\"unsafe\"]` under [capabilities] in package.ipe for durable consent."
}

/// Whether consent is already recorded, without any prompt: the one-off flag or
/// the durable manifest token.
#[must_use]
pub fn pre_accepted(accept_risks_flag: bool, manifest_accept: &BTreeSet<Capability>) -> bool {
    accept_risks_flag || manifest_accept.contains(&Capability::Unsafe)
}

/// The acknowledgment gate: given the program's inferred capabilities and the
/// consent inputs, decide whether the build may proceed.
///
/// - No `unsafe` in the inferred set → the safe path: returns `Ok(())` silently,
///   whatever the flags. There is no ceremony on ordinary code.
/// - `unsafe` present, pre-accepted (flag or manifest) → proceeds silently.
/// - `unsafe` present, an interactive terminal, not pre-accepted → prints the
///   risk and prompts; a `y` proceeds, anything else is a typed refusal.
/// - `unsafe` present, non-interactive, not pre-accepted → **fails closed** with
///   `IPE-S0001` and the remedy. It NEVER blocks on a prompt: a build that hangs
///   waiting for stdin in CI is a worse failure than the risk it guards.
///
/// `stdin`/`stderr` are injected so the interactive path is testable; production
/// passes the real handles.
///
/// # Errors
/// [`CliError::Usage`] carrying `IPE-S0001` when consent is required but
/// absent (a non-interactive build, or an interactive "no").
pub fn gate<R: std::io::BufRead, W: Write>(
    inferred: &BTreeSet<Capability>,
    accept_risks_flag: bool,
    manifest_accept: &BTreeSet<Capability>,
    via: &[String],
    interactive: bool,
    stdin: &mut R,
    stderr: &mut W,
) -> Result<(), CliError> {
    if !inferred.contains(&Capability::Unsafe) {
        // The safe path: no disclosed exposure, nothing to acknowledge.
        return Ok(());
    }
    if pre_accepted(accept_risks_flag, manifest_accept) {
        // Recorded consent (flag or manifest) — proceed silently. Consent is the
        // one-off flag or the durable manifest token; either suffices.
        return Ok(());
    }

    let body = acknowledgment_text(via);
    let remedy = remedy_line();

    if !interactive {
        // Non-interactive / CI: never prompt. Fail closed through the shared
        // typed renderer so IPE-S0001 gains the title-rule, explain footer,
        // and stable JSON schema.
        let diag = SharedDiag::Consent {
            msg: ConsentError::NonInteractive { body },
        };
        return Err(CliError::Pipeline {
            file: PathBuf::new(),
            src: String::new(),
            diag: Box::new(diag),
        });
    }

    // Interactive terminal: disclose, then ask. A non-`y` answer is a typed,
    // fail-closed refusal — the build does not proceed.
    let _ = write!(
        stderr,
        "warning[IPE-S0001]: {body}{remedy}\n  Proceed and accept these risks? [y/N] "
    );
    let _ = stderr.flush();
    let mut answer = String::new();
    // A closed stdin (EOF) reads zero bytes → empty answer → refusal, never a hang.
    let _ = stdin.read_line(&mut answer);
    if answer.trim().eq_ignore_ascii_case("y") {
        return Ok(());
    }
    let diag = SharedDiag::Consent {
        msg: ConsentError::InteractiveDenied {
            body: String::new(),
        },
    };
    Err(CliError::Pipeline {
        file: PathBuf::new(),
        src: String::new(),
        diag: Box::new(diag),
    })
}

/// Whether the current process is attached to an interactive terminal on BOTH
/// stdin and stderr — the precondition for a yes/no prompt.
///
/// A prompt with no readable stdin (a pipe, a CI runner) or no visible stderr
/// would hang or ask invisibly, so either being non-terminal routes to the
/// fail-closed path.
#[must_use]
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn caps(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    #[test]
    fn scan_finds_dotted_unsafe_imports_and_ignores_others() {
        let src = "module Main exposing (main)\n\
                   import Ipe.Html exposing (text)\n\
                   import Ipe.Html.Unsafe exposing (unsafeRaw)\n\
                   import Ipe.Db.Unsafe as U\n\
                   import Ipe.Io as Io\n";
        let via = unsafe_modules_in_sources([src]);
        assert_eq!(via, vec!["Ipe.Db.Unsafe", "Ipe.Html.Unsafe"]);
    }

    #[test]
    fn scan_ignores_the_defining_two_segment_and_non_ipe_paths() {
        // A bare `Ipe.Unsafe` (two segments) is not an escape-hatch submodule, and
        // a non-`Ipe` first segment is user code, not a disclosed hatch.
        let src = "import Ipe.Unsafe\nimport My.Thing.Unsafe\nimport Ipe.Html.Attributes\n";
        assert!(unsafe_modules_in_sources([src]).is_empty());
    }

    #[test]
    fn safe_program_is_never_gated() {
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::new());
        // No `unsafe` capability → Ok regardless of interactivity or flags.
        gate(
            &caps(&[Capability::Network]),
            false,
            &BTreeSet::new(),
            &[],
            false,
            &mut stdin,
            &mut out,
        )
        .expect("safe program proceeds");
        assert!(out.is_empty(), "the safe path prints nothing");
    }

    #[test]
    fn flag_pre_accepts_silently() {
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::new());
        gate(
            &caps(&[Capability::Unsafe]),
            true,
            &BTreeSet::new(),
            &["Ipe.Html.Unsafe".to_owned()],
            false,
            &mut stdin,
            &mut out,
        )
        .expect("--accept-risks proceeds");
        assert!(out.is_empty());
    }

    #[test]
    fn manifest_token_pre_accepts_silently() {
        let mut out = Vec::new();
        let mut stdin = Cursor::new(Vec::new());
        gate(
            &caps(&[Capability::Unsafe]),
            false,
            &caps(&[Capability::Unsafe]),
            &["Ipe.Db.Unsafe".to_owned()],
            false,
            &mut stdin,
            &mut out,
        )
        .expect("manifest accept proceeds");
        assert!(out.is_empty());
    }

    #[test]
    fn non_interactive_without_consent_fails_closed_and_does_not_hang() {
        let mut out = Vec::new();
        // An empty stdin: if the gate ever tried to read interactively it would
        // get EOF, not hang — but non-interactive must not read at all.
        let mut stdin = Cursor::new(Vec::new());
        let err = gate(
            &caps(&[Capability::Unsafe]),
            false,
            &BTreeSet::new(),
            &["Ipe.Html.Unsafe".to_owned()],
            false,
            &mut stdin,
            &mut out,
        )
        .expect_err("non-interactive build without consent fails closed");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0001"), "carries the code: {msg}");
        assert!(msg.contains("Ipe.Html.Unsafe"), "names the module: {msg}");
        assert!(
            msg.contains("cross-site scripting"),
            "names the risk: {msg}"
        );
        assert!(msg.contains("--accept-risks"), "names the remedy: {msg}");
        assert!(
            msg.contains("will not prompt"),
            "states it will not block: {msg}"
        );
    }

    #[test]
    fn interactive_yes_proceeds() {
        let mut out = Vec::new();
        let mut stdin = Cursor::new(b"y\n".to_vec());
        gate(
            &caps(&[Capability::Unsafe]),
            false,
            &BTreeSet::new(),
            &["Ipe.Html.Unsafe".to_owned()],
            true,
            &mut stdin,
            &mut out,
        )
        .expect("an interactive yes proceeds");
        let printed = String::from_utf8(out).expect("utf8");
        assert!(printed.contains("Proceed and accept these risks?"));
    }

    #[test]
    fn interactive_no_refuses() {
        let mut out = Vec::new();
        let mut stdin = Cursor::new(b"n\n".to_vec());
        let err = gate(
            &caps(&[Capability::Unsafe]),
            false,
            &BTreeSet::new(),
            &["Ipe.Html.Unsafe".to_owned()],
            true,
            &mut stdin,
            &mut out,
        )
        .expect_err("an interactive no refuses");
        assert!(err.to_string().contains("IPE-S0001"));
    }

    #[test]
    fn interactive_eof_refuses_rather_than_hangs() {
        let mut out = Vec::new();
        // Terminal claimed interactive but stdin is at EOF (closed): read_line
        // returns 0 bytes, the empty answer is a refusal — no hang.
        let mut stdin = Cursor::new(Vec::new());
        let err = gate(
            &caps(&[Capability::Unsafe]),
            false,
            &BTreeSet::new(),
            &["Ipe.Html.Unsafe".to_owned()],
            true,
            &mut stdin,
            &mut out,
        )
        .expect_err("EOF is a refusal");
        assert!(err.to_string().contains("IPE-S0001"));
    }
}
