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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
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
/// formatter's round-trip guard trips; [`CliError::FmtOutputTooLarge`] when a
/// file's formatted output would pass its cap. Under `--check`, an unformatted
/// file is reported as a non-zero exit via [`CliError::CheckFailed`] carrying
/// the list.
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
            paths,
            check,
            format,
        } => {
            let roots: Vec<PathBuf> =
                paths.map_or_else(|| vec![PathBuf::from(".")], |p| p.iter().cloned().collect());
            run_fmt_inplace(&roots, check, format)
        }
    }
}

/// The most source and formatted text one in-place run holds before writing.
///
/// Every rewrite is held until every file has formatted, so the held text is
/// bounded like a build's summed source read.
const HELD_REWRITE_BYTES: u64 = crate::source_snapshot::SOURCE_TREE_READ_CAP;

/// Where an in-place run reports its refusals: the human screen, or the
/// machine stream a `--check --json` / `--check --plain` scan writes.
#[derive(Debug, Clone, Copy)]
enum RefusalSink {
    /// The human error screen on stderr.
    Human,
    /// The machine error envelope of this format on stderr.
    Machine(crate::cli_args::OutputFormat),
}

impl RefusalSink {
    /// The sink of a run reporting in `format`.
    const fn of(format: crate::cli_args::OutputFormat) -> Self {
        match format {
            crate::cli_args::OutputFormat::Human => Self::Human,
            crate::cli_args::OutputFormat::Json | crate::cli_args::OutputFormat::Plain => {
                Self::Machine(format)
            }
        }
    }

    /// Report a refusal the run met before its last one.
    fn report(self, err: &CliError) {
        match self {
            Self::Human => crate::screen::report_error(err),
            Self::Machine(format) => {
                // The returned sentinel is the run's to return, not this one's.
                let _ = crate::driver::emit_machine_error(format, "fmt", err);
            }
        }
    }

    /// The run's final error: as is for a human run, or written as a machine
    /// envelope and replaced by the already-emitted sentinel.
    fn finish(self, err: CliError) -> CliError {
        match self {
            Self::Human => err,
            Self::Machine(format) => crate::driver::emit_machine_error(format, "fmt", &err),
        }
    }

    /// Keep `err` as the run's refusal, reporting the one it replaces.
    fn keep(self, refusal: &mut Option<CliError>, err: CliError) {
        if let Some(earlier) = refusal.replace(err) {
            self.report(&earlier);
        }
    }
}

/// Format every `.ipe` file `roots` name, in place, all or nothing.
///
/// Every root is resolved and every file formatted before any file is
/// written: a missing root, an unparsable file or any other refusal leaves
/// every file as it was. Under `--check`, `format` selects how the unformatted
/// set and every refusal are reported: the human screen (default), or a
/// machine `--json` / `--plain` stream.
fn run_fmt_inplace(
    roots: &[PathBuf],
    check: bool,
    format: crate::cli_args::OutputFormat,
) -> Result<(), CliError> {
    let sink = RefusalSink::of(format);
    let files = collect_fmt_files(roots, WalkLimits::DEFAULT).map_err(|e| sink.finish(e))?;
    if files.is_empty() {
        let named = roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        return Err(sink.finish(CliError::Usage(crate::text::msg::fmt_no_files(&named))));
    }
    if check {
        let mut unformatted: Vec<PathBuf> = Vec::new();
        format_each(&files, sink, |file, _, _| {
            unformatted.push(file.path.clone());
            Ok(())
        })
        .map_err(|e| sink.finish(e))?;
        return report_check(&unformatted, format);
    }
    let mut plan: Vec<Rewrite<'_>> = Vec::new();
    let mut held: u64 = 0;
    format_each(&files, sink, |file, source, formatted| {
        hold_rewrite(
            &mut held,
            HELD_REWRITE_BYTES,
            &file.path,
            &source,
            &formatted,
        )?;
        plan.push(Rewrite {
            file,
            source,
            formatted,
        });
        Ok(())
    })?;
    write_rewrites(plan, sink)
}

/// One file whose formatted text differs from the source it was read as.
struct Rewrite<'f> {
    /// The file, as collected.
    file: &'f FmtFile,
    /// The source exactly as read.
    source: String,
    /// The formatter's output for `source`.
    formatted: String,
}

/// Read and format every file, handing each one that changes to `changed`.
///
/// Every refusal is reported to `sink` and the last one returned, so a caller
/// that writes only on `Ok` writes nothing when any file is refused. An error
/// from `changed` stops the run at once.
fn format_each<'f>(
    files: &'f [FmtFile],
    sink: RefusalSink,
    mut changed: impl FnMut(&'f FmtFile, String, String) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut refusal: Option<CliError> = None;
    for file in files {
        let outcome = read_fmt_file(file).and_then(|source| {
            format_source(&source)
                .map(|formatted| (source, formatted))
                .map_err(|e| fmt_err_to_cli(&file.path, e))
        });
        match outcome {
            Err(err) => sink.keep(&mut refusal, err),
            // After a refusal nothing is written; the rest are formatted only
            // to report their own refusals.
            Ok((source, formatted)) if source != formatted && refusal.is_none() => {
                changed(file, source, formatted)?;
            }
            Ok(_) => {}
        }
    }
    refusal.map_or(Ok(()), Err)
}

/// Charge one held rewrite of `path` to `held`, refusing past `cap` bytes.
fn hold_rewrite(
    held: &mut u64,
    cap: u64,
    path: &Path,
    source: &str,
    formatted: &str,
) -> Result<(), CliError> {
    let size = u64::try_from(source.len().saturating_add(formatted.len())).unwrap_or(u64::MAX);
    *held = held.saturating_add(size);
    if *held > cap {
        return Err(CliError::Usage(crate::text::msg::fmt_held_bytes_limit(
            &cap,
            &path.display(),
        )));
    }
    Ok(())
}

/// Write every planned rewrite while its file still holds the source it was formatted from.
///
/// Each file is written on its own: one that fails, or was edited since it
/// was read, is left as it is and reported, and every other file is still
/// written. Every written file is named as it is written.
fn write_rewrites(plan: Vec<Rewrite<'_>>, sink: RefusalSink) -> Result<(), CliError> {
    let mut refusal: Option<CliError> = None;
    let mut changed: Vec<PathBuf> = Vec::new();
    for rewrite in plan {
        match write_rewrite(&rewrite) {
            Ok(true) => crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Text,
                crate::text::msg::fmt_formatted(&rewrite.file.path.display()).as_str(),
            ),
            Ok(false) => changed.push(rewrite.file.path.clone()),
            Err(err) => sink.keep(&mut refusal, err),
        }
    }
    if !changed.is_empty() {
        let list =
            crate::text::TerminalBlock::lines(changed.iter().map(|p| format!("  {}", p.display())));
        sink.keep(
            &mut refusal,
            CliError::Usage(crate::text::msg::fmt_changed_while_formatting(&list)),
        );
    }
    refusal.map_or(Ok(()), Err)
}

/// Write one planned rewrite; `false` when its file no longer holds the source it was formatted from.
fn write_rewrite(rewrite: &Rewrite<'_>) -> Result<bool, CliError> {
    let file = rewrite.file;
    match &file.origin {
        FmtOrigin::Named => Ok(matches!(
            crate::driver::rewrite_user_file_if_unchanged(
                &file.path,
                &rewrite.source,
                &rewrite.formatted,
                crate::RewriteKind::Lossless,
            )?,
            crate::driver::IfUnchanged::Written(_)
        )),
        FmtOrigin::Walked(root) => {
            if crate::io_bounded::read_walked_source(&file.path)? != rewrite.source {
                return Ok(false);
            }
            crate::rewrite_walked_file(
                root,
                &file.path,
                &rewrite.formatted,
                crate::RewriteKind::Lossless,
            )?;
            Ok(true)
        }
    }
}

/// Read `file` the way its [`FmtOrigin`] allows.
fn read_fmt_file(file: &FmtFile) -> Result<String, CliError> {
    match file.origin {
        FmtOrigin::Named => {
            crate::io_bounded::read_user_named(&file.path, crate::io_bounded::SOURCE_CAP)
        }
        FmtOrigin::Walked(_) => crate::io_bounded::read_walked_source(&file.path),
    }
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
            Err(CliError::CheckFailed(
                crate::text::msg::fmt_unformatted_files(&list),
            ))
        }
    }
}

/// A source read from standard input and its formatted text.
#[derive(Debug)]
pub struct StdinFormatted {
    /// The source exactly as read.
    pub source: String,
    /// The formatter's output for `source`.
    pub formatted: String,
}

/// Read a source from `reader` the way `ipe fmt` reads stdin, and format it.
///
/// The read stops at [`crate::io_bounded::SOURCE_READ_CAP`], the same ceiling a
/// source file is read under.
///
/// # Errors
/// [`CliError::FileTooLarge`] when the input passes the read cap;
/// [`CliError::Io`] when it cannot be read or is not UTF-8; otherwise the
/// errors of [`run_fmt`] for a file named `<stdin>`.
pub fn format_stdin_from(reader: impl Read) -> Result<StdinFormatted, CliError> {
    let source = crate::io_bounded::read_stream_capped(
        reader,
        Path::new("<stdin>"),
        crate::io_bounded::SOURCE_READ_CAP,
    )?;
    let formatted = format_source(&source).map_err(|e| fmt_err_to_cli(Path::new("<stdin>"), e))?;
    Ok(StdinFormatted { source, formatted })
}

/// Format stdin to stdout. When `check` is true, print a diff instead.
fn run_fmt_stdin(check: bool) -> Result<(), CliError> {
    run_fmt_stdin_from(std::io::stdin().lock(), check)
}

/// [`run_fmt_stdin`] over any reader.
fn run_fmt_stdin_from(reader: impl Read, check: bool) -> Result<(), CliError> {
    let StdinFormatted {
        source: src,
        formatted,
    } = format_stdin_from(reader)?;

    if check {
        if formatted != src {
            // Print a unified diff for CI consumption.
            diff_eprint("<stdin>", &src, &formatted);
            return Err(CliError::CheckFailed(
                crate::text::msg::fmt_stdin_unformatted(),
            ));
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
        FmtError::RoundTrip(fault) => CliError::Pipeline {
            file: file.to_path_buf(),
            src: String::new(),
            diag: Box::new(Diagnostic::CompilerBug {
                where_: "ipe fmt",
                detail: fault.to_string(),
            }),
        },
        FmtError::Limit(FmtLimit::OutputBytes { cap }) => CliError::FmtOutputTooLarge {
            file: file.to_path_buf(),
            cap,
        },
    }
}

/// How one file reached an `ipe fmt` run, which decides how it is read and rewritten.
enum FmtOrigin {
    /// Named on the command line: a final symlink is followed.
    Named,
    /// Found by walking this named directory: it must resolve inside it.
    Walked(PathBuf),
}

/// One file an `ipe fmt` run formats.
struct FmtFile {
    /// The path as the user named it or the walk reached it.
    path: PathBuf,
    /// How it reached the run.
    origin: FmtOrigin,
}

/// The ceilings one `ipe fmt` run's file collection is held to, summed over every root.
///
/// The module-discovery ceilings a build's walk is held to: a directory past
/// `depth` below its root, a named path or listed entry past `entries`, or a
/// file past `files` refuses the run before any file is read.
#[derive(Debug, Clone, Copy)]
struct WalkLimits {
    depth: usize,
    entries: usize,
    files: usize,
}

impl WalkLimits {
    /// The ceilings every `ipe fmt` run is held to.
    const DEFAULT: Self = Self {
        depth: crate::project::MAX_DISCOVERY_DEPTH,
        entries: crate::project::MAX_DISCOVERY_ENTRIES,
        files: crate::project::MAX_DISCOVERED_MODULES,
    };
}

/// One collection's running counts against its [`WalkLimits`].
struct FmtWalk {
    limits: WalkLimits,
    examined: usize,
    found: usize,
}

impl FmtWalk {
    /// Count one more named path or listed entry, refusing past the entry ceiling.
    fn examine(&mut self, at: &Path) -> Result<(), CliError> {
        self.examined = self.examined.saturating_add(1);
        if self.examined > self.limits.entries {
            return Err(walk_limit(crate::text::msg::fmt_walk_too_many_entries(
                &self.limits.entries,
                &at.display(),
            )));
        }
        Ok(())
    }

    /// Count one more file to format, refusing past the file ceiling.
    fn find(&mut self, at: &Path) -> Result<(), CliError> {
        self.found = self.found.saturating_add(1);
        if self.found > self.limits.files {
            return Err(walk_limit(crate::text::msg::fmt_walk_too_many_files(
                &self.limits.files,
                &at.display(),
            )));
        }
        Ok(())
    }

    /// Every file `root` names: itself when it is a file, else every `.ipe`
    /// under it, never through a symlink and never in a generated build tree.
    fn root(&mut self, root: &Path) -> Result<Vec<FmtFile>, CliError> {
        self.examine(root)?;
        if root.is_file() {
            self.find(root)?;
            return Ok(vec![FmtFile {
                path: root.to_path_buf(),
                origin: FmtOrigin::Named,
            }]);
        }
        if !root.is_dir() {
            return Err(CliError::Usage(crate::text::msg::fmt_no_such_path(
                &root.display(),
            )));
        }
        let mut out: Vec<FmtFile> = Vec::new();
        let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > self.limits.depth {
                return Err(walk_limit(crate::text::msg::fmt_walk_too_deep(
                    &self.limits.depth,
                    &dir.display(),
                )));
            }
            let entries = fs::read_dir(&dir).map_err(|e| CliError::Io {
                path: dir.clone(),
                source: e,
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| CliError::Io {
                    path: dir.clone(),
                    source: e,
                })?;
                self.examine(&dir)?;
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
                    stack.push((path, depth.saturating_add(1)));
                } else if file_type.is_file()
                    && path.extension().and_then(|e| e.to_str()) == Some("ipe")
                {
                    self.find(&dir)?;
                    out.push(FmtFile {
                        path,
                        origin: FmtOrigin::Walked(root.to_path_buf()),
                    });
                }
            }
        }
        Ok(out)
    }
}

/// A collection ceiling's refusal.
fn walk_limit(detail: crate::text::Message) -> CliError {
    CliError::DiscoveryLimitReached {
        detail: detail.into(),
    }
}

/// Every file `roots` name, once each, in the order of the file each path reaches.
///
/// Each root is resolved before any file is read, so a missing root refuses
/// the run. Two paths reaching the same file (a repeated argument, a file
/// also inside a named directory, a link) keep the first in argument order.
/// The collection is held to `limits`, summed over every root.
fn collect_fmt_files(roots: &[PathBuf], limits: WalkLimits) -> Result<Vec<FmtFile>, CliError> {
    let mut walk = FmtWalk {
        limits,
        examined: 0,
        found: 0,
    };
    let mut by_file: BTreeMap<PathBuf, FmtFile> = BTreeMap::new();
    for root in roots {
        for file in walk.root(root)? {
            let real = fs::canonicalize(&file.path).map_err(|e| CliError::Io {
                path: file.path.clone(),
                source: e,
            })?;
            by_file.entry(real).or_insert(file);
        }
    }
    Ok(by_file.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::{Header, error_screen};

    const UNFORMATTED: &str = "module M exposing (x)\n\nx =\n  1\n";

    /// The first line of the `ipe fmt` help page.
    const USAGE_FIRST_LINE: &str = "Format Ipê source files.";

    /// The synopsis line of the `ipe fmt` help page.
    const USAGE_SYNOPSIS: &str = "ipe fmt [<path>...]";

    /// The human error screen of `err`, header omitted.
    fn screen_of(err: &CliError) -> String {
        error_screen(err, false)
            .map(|screen| screen.render(Header::Omitted))
            .unwrap_or_default()
    }

    fn assert_verdict_without_usage(err: &CliError) {
        assert!(matches!(err, CliError::CheckFailed(_)), "{err:?}");
        assert_eq!(err.machine_kind(), "check-failed");
        let screen = screen_of(err);
        assert!(!screen.contains(USAGE_FIRST_LINE), "{screen}");
        assert!(!screen.contains(USAGE_SYNOPSIS), "{screen}");
        assert!(!screen.contains("Options"), "{screen}");
    }

    /// A dirty stdin check is a verdict: its screen carries no usage page.
    #[test]
    fn a_dirty_stdin_check_is_a_verdict_not_usage() {
        let err = run_fmt_stdin_from(UNFORMATTED.as_bytes(), true).err();
        assert!(err.is_some(), "a dirty stdin check must fail");
        let Some(err) = err else {
            return;
        };
        assert_verdict_without_usage(&err);
        assert!(screen_of(&err).contains("stdin is not formatted"));
    }

    /// A formatted stdin passes the check.
    #[test]
    fn a_formatted_stdin_check_passes() {
        let canonical = format_source(UNFORMATTED).unwrap_or_default();
        assert!(!canonical.is_empty(), "the fixture must format");
        assert!(run_fmt_stdin_from(canonical.as_bytes(), true).is_ok());
    }

    /// A dirty directory check names the files and carries no usage page.
    #[test]
    fn a_dirty_directory_check_is_a_verdict_not_usage() {
        let err = report_check(
            &[PathBuf::from("src/A.ipe"), PathBuf::from("src/B.ipe")],
            crate::cli_args::OutputFormat::Human,
        )
        .err();
        assert!(err.is_some(), "a dirty check must fail");
        let Some(err) = err else {
            return;
        };
        assert_verdict_without_usage(&err);
        let screen = screen_of(&err);
        assert!(screen.contains("src/A.ipe"), "{screen}");
        assert!(screen.contains("src/B.ipe"), "{screen}");
    }

    /// Held rewrite text is accepted up to the ceiling and refused one byte past it.
    #[test]
    fn held_rewrite_text_is_refused_one_byte_past_the_ceiling() {
        let path = Path::new("A.ipe");
        let mut held = 0;
        assert!(hold_rewrite(&mut held, 10, path, "abcd", "efghij").is_ok());
        assert_eq!(held, 10);
        let past = hold_rewrite(&mut held, 10, path, "", "x");
        assert!(
            matches!(&past, Err(CliError::Usage(m)) if m.contains("A.ipe")),
            "{past:?}"
        );

        let mut held = 0;
        let over = hold_rewrite(&mut held, 10, path, "abcde", "fghijk");
        assert!(matches!(over, Err(CliError::Usage(_))), "{over:?}");
    }

    /// A fresh scratch directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!("ipe-fmt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok(), "{}", dir.display());
        dir
    }

    /// Ceilings far above any tree a test builds, then `change`d.
    fn limits(change: impl FnOnce(&mut WalkLimits)) -> WalkLimits {
        let mut limits = WalkLimits {
            depth: 64,
            entries: 1_000,
            files: 1_000,
        };
        change(&mut limits);
        limits
    }

    /// Whether collecting `roots` under `limits` is the walk-ceiling refusal.
    fn walk_refused(roots: &[PathBuf], limits: WalkLimits) -> bool {
        matches!(
            collect_fmt_files(roots, limits).err(),
            Some(CliError::DiscoveryLimitReached { .. })
        )
    }

    /// Each collection ceiling admits a tree at it and refuses one past it.
    #[test]
    fn the_file_collection_is_refused_one_past_each_ceiling() {
        let dir = scratch("walk-limits");
        let deep = dir.join("a").join("b");
        assert!(fs::create_dir_all(&deep).is_ok());
        assert!(fs::write(dir.join("A.ipe"), UNFORMATTED).is_ok());
        assert!(fs::write(dir.join("a").join("B.ipe"), UNFORMATTED).is_ok());
        let roots = [dir.clone()];

        // `b` sits two levels below the root.
        assert!(collect_fmt_files(&roots, limits(|l| l.depth = 2)).is_ok());
        assert!(walk_refused(&roots, limits(|l| l.depth = 1)));
        // The root, `A.ipe`, `a`, `B.ipe` and `b` are five entries.
        assert!(collect_fmt_files(&roots, limits(|l| l.entries = 5)).is_ok());
        assert!(walk_refused(&roots, limits(|l| l.entries = 4)));
        // Two files, counted again when a second root reaches one of them.
        assert!(collect_fmt_files(&roots, limits(|l| l.files = 2)).is_ok());
        assert!(walk_refused(&roots, limits(|l| l.files = 1)));
        let twice = [dir.clone(), dir.join("A.ipe")];
        assert!(collect_fmt_files(&twice, limits(|l| l.files = 3)).is_ok());
        assert!(walk_refused(&twice, limits(|l| l.files = 2)));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A write that fails leaves the files after it written, and is reported.
    #[test]
    fn a_failed_write_does_not_stop_the_rest() {
        let dir = scratch("write-continues");
        let gone = FmtFile {
            path: dir.join("Gone.ipe"),
            origin: FmtOrigin::Named,
        };
        let kept = FmtFile {
            path: dir.join("Kept.ipe"),
            origin: FmtOrigin::Named,
        };
        assert!(fs::write(&kept.path, UNFORMATTED).is_ok());
        let plan = vec![
            Rewrite {
                file: &gone,
                source: UNFORMATTED.to_owned(),
                formatted: String::from("formatted\n"),
            },
            Rewrite {
                file: &kept,
                source: UNFORMATTED.to_owned(),
                formatted: String::from("formatted\n"),
            },
        ];
        let res = write_rewrites(plan, RefusalSink::Human);
        assert!(matches!(res, Err(CliError::Io { .. })), "{res:?}");
        assert_eq!(
            fs::read_to_string(&kept.path).unwrap_or_default(),
            "formatted\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A file edited since it was read is left as it is and named.
    #[test]
    fn a_file_changed_since_it_was_read_is_left_and_named() {
        let dir = scratch("write-changed");
        let edited = FmtFile {
            path: dir.join("Edited.ipe"),
            origin: FmtOrigin::Walked(dir.clone()),
        };
        assert!(fs::write(&edited.path, "edited\n").is_ok());
        let plan = vec![Rewrite {
            file: &edited,
            source: UNFORMATTED.to_owned(),
            formatted: String::from("formatted\n"),
        }];
        let res = write_rewrites(plan, RefusalSink::Human);
        assert!(
            matches!(&res, Err(CliError::Usage(m)) if m.contains("Edited.ipe")),
            "{res:?}"
        );
        assert_eq!(
            fs::read_to_string(&edited.path).unwrap_or_default(),
            "edited\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A malformed command line still renders the usage page.
    #[test]
    fn a_malformed_fmt_command_line_still_renders_usage() {
        let err = crate::run_cli(&["fmt".to_owned(), "--no-such-flag".to_owned()]).err();
        assert!(
            matches!(err, Some(CliError::CommandUsage { .. })),
            "{err:?}"
        );
        let screen = err.as_ref().map(screen_of).unwrap_or_default();
        assert!(screen.contains(USAGE_FIRST_LINE), "{screen}");
    }
}
