//! `ipe fmt` — the Ipê source formatter.
//!
//! A semantics- and comment-preserving pretty-printer for `.ipe` source that
//! ports the layout decisions of `elm-format` (Ipê's syntax is Elm-derived, so
//! the target style is "how `elm-format` would format the equivalent Elm").
//!
//! # How it works
//!
//! The formatter never re-lexes ad hoc for structure: it parses the REAL
//! [`ipe_syntax::Module`] via [`ipe_parse::parse_module`] and pretty-prints
//! from that tree, so the output is a function of the parsed program, not of a
//! bespoke second grammar. Comments — which the parser discards as trivia — are
//! recovered by a separate source scan ([`scan_comments`]) that reuses the same
//! comment shapes the lexer's `skip_trivia` recognises (`--` line comments and
//! nestable `{- -}` block comments), and are re-attached to:
//! * the top-level declaration whose span they immediately precede (leading
//!   comments) or to the end of the module (trailing comments);
//! * the annotation↔definition gap in a `Value` (between the type annotation
//!   and the binding name);
//! * `case` arms, `let` bindings, and `type alias` bodies (comments in the
//!   inter-node gaps inside each construct).
//!
//! A comment-count guard in [`format_source`] catches any regression: if the
//! formatted output contains fewer comments than the input, the formatter fails
//! closed with [`FmtError::RoundTrip`] rather than silently dropping them.
//!
//! # Guarantees
//!
//! * **Semantics-preserving**: [`format_source`] re-parses its own output and
//!   compares the resulting AST to the input AST; a mismatch is caught by the
//!   [`FmtError::RoundTrip`] compiler-bug guard rather than a silent
//!   corruption. (The comparison ignores spans — only structure and values
//!   matter.)
//! * **Comment-preserving**: every comment in the input appears in the output.
//! * **Bounded**: the output of one file may not pass
//!   [`OutputCap::for_input`]; a file it would pass is refused and
//!   left unchanged.
//! * **Idempotent**: `format_source(format_source(x)) == format_source(x)`. The
//!   `ipe fmt` fixtures assert this over records / lists / tuples / `case` /
//!   `let` / `if` / comments, and the scaffolded `ipe init` template is a fixed
//!   point (it is already elm-format style).
//!
//! # Ported vs. deferred elm-format rules
//!
//! Ported: module header + `exposing`, import block (sorted, one blank line
//! before the first declaration), top-level definitions separated by one blank
//! line with the type annotation directly above its definition, 4-space
//! indentation, `case … of` / `let … in` / `if … then … else` layout,
//! records / lists / tuples in leading-comma multiline style (single-line when
//! they fit within the 80-column budget), operator spacing, function
//! application layout, and `|>` / `<|` pipe operators. Deferred (documented in
//! the module test suite and the command's report): redundant-parenthesis
//! removal (the AST does not retain user parens), documentation-comment
//! (`{-| … -}`) re-flowing, and per-import `exposing`-list column wrapping.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ipe_diagnostics::Diagnostic;

// The formatting engine lives in the `ipe_fmt` crate so both this CLI and the
// LSP formatting provider can share it. Re-export its public surface so
// `ipe::fmt::format_source` (used here and by the integration tests) resolves.
pub use ipe_fmt::{FmtError, FmtLimit, OutputCap, format_source};

use crate::CliError;
/// Run the `fmt` subcommand.
///
/// # Errors
/// [`CliError::Usage`] on flag misuse; [`CliError::Io`] on a filesystem
/// failure; [`CliError::Pipeline`] when a file cannot be parsed or the
/// formatter's round-trip guard trips; [`CliError::Usage`] when a file's
/// formatted output would pass its cap. Under `--check`, an unformatted file is
/// reported as a non-zero exit via [`CliError::Usage`] carrying the list.
pub fn run_fmt(rest: &[String]) -> Result<(), CliError> {
    // `--help` / `-h` is a request for output, not an error — honour it before
    // the typed parse (which treats every dashed token as a flag to validate).
    // The page is the single source of truth in `help::command`, identical to
    // what the top-level dispatcher prints for `ipe fmt --help`.
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        if let Some(page) = crate::help::command("fmt", &std::io::stdout()) {
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .guttered(&page)
                .emit();
        }
        return Ok(());
    }
    let mode = crate::cli_args::parse_fmt(rest)?;
    match mode {
        crate::cli_args::FmtMode::Stdin => run_fmt_stdin(false),
        crate::cli_args::FmtMode::StdinCheck => run_fmt_stdin(true),
        crate::cli_args::FmtMode::InPlace {
            path,
            check,
            format,
        } => run_fmt_inplace(path.as_deref(), check, format),
    }
}

/// Format every `.ipe` under `root` in place.
///
/// `None` means the current directory `.`. Under `--check`, `format` selects how
/// the unformatted set is reported: the human list (default), or a machine
/// `--json` / `--plain` file list.
fn run_fmt_inplace(
    path: Option<&str>,
    check: bool,
    format: crate::cli_args::OutputFormat,
) -> Result<(), CliError> {
    let root = PathBuf::from(path.unwrap_or("."));
    let files = collect_ipe_files(&root)?;
    if files.is_empty() {
        return Err(CliError::Usage(crate::text::msg::fmt_no_files(
            &root.display(),
        )));
    }

    // A file reached by walking a directory must stay inside it; only an
    // explicitly named file may be a symlink to elsewhere.
    let walked = !root.is_file();
    let mut unformatted: Vec<PathBuf> = Vec::new();
    for file in &files {
        let src =
            crate::io_bounded::read_to_string_capped(file, crate::io_bounded::SOURCE_READ_CAP)?;
        let formatted = format_source(&src).map_err(|e| fmt_err_to_cli(file, e))?;
        if check {
            if formatted != src {
                unformatted.push(file.clone());
            }
        } else if formatted != src {
            if walked {
                crate::rewrite_walked_file(&root, file, &formatted, crate::RewriteKind::Lossless)?;
            } else {
                crate::rewrite_user_file(file, &formatted, crate::RewriteKind::Lossless)?;
            }
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Text,
                &format!("formatted {}", file.display()),
            );
        }
    }

    if check {
        return report_check(&unformatted, format);
    }

    Ok(())
}

/// Report a `--check` scan's result in the requested [`OutputFormat`].
///
/// A machine form (`--json` / `--plain`) always emits its list to stdout — empty
/// on a clean scan (exit 0), or the unformatted paths on a dirty one — then, when
/// non-empty, returns the already-emitted sentinel so the exit is non-zero with
/// no second message. The human form prints nothing on a clean scan and the
/// actionable list on a dirty one.
fn report_check(
    unformatted: &[PathBuf],
    format: crate::cli_args::OutputFormat,
) -> Result<(), CliError> {
    use crate::cli_args::{OutputFormat, json};

    match format {
        OutputFormat::Json => {
            let paths: Vec<String> = unformatted
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
            let payload = json::object(&[("unformatted", json::string_array(&refs))]);
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &format!("{payload}\n"));
            if unformatted.is_empty() {
                Ok(())
            } else {
                Err(CliError::DiagnosticJsonEmitted)
            }
        }
        OutputFormat::Plain => {
            let mut lines = String::new();
            for p in unformatted {
                lines.push_str(&p.display().to_string());
                lines.push('\n');
            }
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &lines);
            if unformatted.is_empty() {
                Ok(())
            } else {
                Err(CliError::DiagnosticJsonEmitted)
            }
        }
        OutputFormat::Human => {
            if unformatted.is_empty() {
                return Ok(());
            }
            let list = crate::text::TerminalBlock::lines(
                unformatted.iter().map(|p| format!("  {}", p.display())),
            );
            Err(CliError::Usage(crate::text::msg::fmt_unformatted_files(
                &list,
            )))
        }
    }
}

/// Format stdin to stdout. When `check` is true, print a diff instead.
fn run_fmt_stdin(check: bool) -> Result<(), CliError> {
    let src = crate::io_bounded::read_opened_capped(
        std::io::stdin().lock(),
        Path::new("<stdin>"),
        crate::io_bounded::SOURCE_READ_CAP,
    )?;

    let formatted =
        format_source(&src).map_err(|e| fmt_err_to_cli(&PathBuf::from("<stdin>"), e))?;

    if check {
        if formatted != src {
            // Print a unified diff for CI consumption.
            diff_eprint("<stdin>", &src, &formatted);
            return Err(CliError::Usage(crate::text::msg::fmt_stdin_unformatted()));
        }
    } else {
        std::io::Write::write_all(&mut std::io::stdout(), formatted.as_bytes()).map_err(|e| {
            CliError::Io {
                path: PathBuf::from("<stdout>"),
                source: e,
            }
        })?;
    }

    Ok(())
}

/// Print a human-readable diff between `original` and `formatted` to stderr.
fn diff_eprint(label: &str, original: &str, formatted: &str) {
    let orig_lines: Vec<&str> = original.lines().collect();
    let fmt_lines: Vec<&str> = formatted.lines().collect();

    // Simple line-by-line diff — good enough for formatter output where
    // changes are typically whitespace-only and spread across the file.
    let mut out = String::new();
    let _ = writeln!(out, "--- {label}");
    let _ = writeln!(out, "+++ {label} (formatted)");

    let max = orig_lines.len().max(fmt_lines.len());
    for i in 0..max {
        let o = orig_lines.get(i).copied().unwrap_or("");
        let f = fmt_lines.get(i).copied().unwrap_or("");
        if o != f {
            let _ = writeln!(out, "-{o}");
            let _ = writeln!(out, "+{f}");
        }
    }

    // SAFETY: diff_eprint is only called in the `--check` path, which
    // typically targets stderr.  We write to stdout here to stay consistent
    // with how other formatters surface diffs (rustfmt prints to stdout).
    let _ = std::io::Write::write_all(&mut std::io::stdout(), out.as_bytes());
}

/// Map a [`FmtError`] onto the driver's [`CliError`] channel.
fn fmt_err_to_cli(file: &Path, e: FmtError) -> CliError {
    match e {
        FmtError::Parse { src, diag } => CliError::Pipeline {
            file: file.to_path_buf(),
            src,
            diag: Box::new(diag),
        },
        FmtError::RoundTrip { detail } => CliError::Pipeline {
            file: file.to_path_buf(),
            src: String::new(),
            diag: Box::new(Diagnostic::CompilerBug {
                where_: "ipe fmt",
                detail,
            }),
        },
        FmtError::Limit(FmtLimit::OutputBytes { cap }) => CliError::Usage(
            crate::text::msg::fmt_output_too_large(&file.display(), &cap),
        ),
    }
}

/// Collect every `.ipe` file governed by `root`: a single file if `root` is one,
/// otherwise every `.ipe` under the directory tree (deterministically sorted).
fn collect_ipe_files(root: &Path) -> Result<Vec<PathBuf>, CliError> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !root.is_dir() {
        return Err(CliError::Usage(crate::text::msg::fmt_no_such_path(
            &root.display(),
        )));
    }
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| CliError::Io {
            path: dir.clone(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| CliError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| CliError::Io {
                path: path.clone(),
                source: e,
            })?;
            if file_type.is_dir() {
                // Skip a generated build tree — never a source directory.
                if entry.file_name() == "out" || entry.file_name() == "target" {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("ipe")
            {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
