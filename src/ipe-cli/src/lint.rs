//! `ipe lint [<path>]` (+ `--fix`) — extensible static analysis over `.ipe`
//! source.
//!
//! The command loads the project's own (user) modules through the SAME
//! resolution path `ipe build` uses — never the injected stdlib — reads an
//! optional `lint.ipe`, runs every enabled rule over the parsed source, and
//! renders each finding compiler-style. With `--fix` it applies every
//! machine-applicable (semantics-preserving) rewrite and reports what changed;
//! otherwise a surviving finding at or above the configured gate severity exits
//! non-zero for CI.
//!
//! `--json` emits findings as `{"schema":"ipe.cli.lint/1","findings":[…]}`.
//! `--plain` prints one line per finding: `<severity>:<file>:<line>:<col>: <message>`.
//! Both forms are mutually exclusive with each other and fail closed against
//! `--fix` (a data form must not trigger mutations — the same rule `health` uses).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe_lint::{LintConfig, SourceModule};

use crate::screen::{self, Screen, Stream, Tone};
use crate::{CliError, cli_args, text, watch};

/// The `lint.ipe` file name, resolved next to a project's `package.ipe` (or in
/// the current directory for a single-file lint).
const LINT_IPE: &str = "lint.ipe";

/// Parsed `ipe lint` arguments.
pub(crate) struct LintArgs {
    /// The path to lint: a `.ipe` file or a project directory. Defaults to the
    /// current project.
    pub(crate) entry: Option<String>,
    /// Apply every machine-applicable fix instead of only reporting.
    pub(crate) fix: bool,
    /// The output format for the findings report.
    pub(crate) format: cli_args::OutputFormat,
}

/// Parse `ipe lint` arguments: an optional positional path, `--fix`, and the
/// shared `--json`/`--plain` output-format flags.
///
/// `--fix` and a data form (`--json`/`--plain`) are mutually exclusive: a data
/// form is a read-only observation; `--fix` mutates sources. The two must not
/// be combined (same rule as `health --yes --json`).
///
/// # Errors
/// [`CliError::UsageOwned`] on an unknown flag, a second positional, or
/// `--fix` combined with `--json`/`--plain`.
pub(crate) fn parse_lint_args(rest: &[String]) -> Result<LintArgs, CliError> {
    let mut entry: Option<String> = None;
    let mut fix = false;
    let mut format: Option<cli_args::OutputFormat> = None;
    for arg in rest {
        if cli_args::consume_format_flag(&mut format, arg, "lint")? {
            continue;
        }
        match arg.as_str() {
            "--fix" => fix = true,
            flag if flag.starts_with('-') => {
                return Err(crate::cli_args::usage_unknown_flag("lint", flag));
            }
            positional => {
                if entry.is_some() {
                    return Err(CliError::Usage(text::lint_single_path()));
                }
                entry = Some(positional.to_owned());
            }
        }
    }
    let format = format.unwrap_or_default();
    if fix && format != cli_args::OutputFormat::Human {
        return Err(CliError::UsageOwned(
            text::lint_fix_with_format().to_owned(),
        ));
    }
    Ok(LintArgs { entry, fix, format })
}

/// `ipe lint [<path>]` — run the linter, printing findings (or applying fixes).
///
/// # Errors
/// [`CliError::Usage`] on misuse; [`CliError::Io`] on a filesystem failure;
/// [`CliError::Pipeline`] if an entry file fails to parse; [`CliError::UsageOwned`]
/// for a malformed `lint.ipe`; [`CliError::LintGateFailed`] when a surviving
/// finding is at or above the gate severity (report path only).
pub(crate) fn run_lint(rest: &[String]) -> Result<(), CliError> {
    let args = parse_lint_args(rest)?;
    let entry = match args.entry {
        Some(e) => PathBuf::from(e),
        None => PathBuf::from(crate::default_entry()?),
    };

    let resolved = watch::resolve_project_sources(&entry, None)?;

    // The config lives next to the resolved manifest, or in the entry's
    // directory for a single-file lint. Absent → defaults.
    let config = load_config(&resolved.blame_path)?;

    // Map every user module to its source and file path (for rendering).
    let mut paths: BTreeMap<Vec<String>, PathBuf> = BTreeMap::new();
    let mut modules: Vec<SourceModule> = Vec::new();
    for (module, (path, source)) in &resolved.sources {
        paths.insert(module.clone(), path.clone());
        modules.push(SourceModule {
            module: module.clone(),
            source: source.clone(),
        });
    }

    if args.fix {
        // Fixes reach modules found by walking the project, so each rewrite must
        // stay inside it (the manifest's directory, or a single file's own).
        let root = resolved
            .blame_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        return apply_and_report(&modules, &config, &paths, &root);
    }
    report_findings(&modules, &config, &paths, args.format)
}

/// Read `lint.ipe` from the directory holding `blame_path` (the resolved
/// manifest or entry file), returning defaults when none exists.
fn load_config(blame_path: &Path) -> Result<LintConfig, CliError> {
    let dir = blame_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let lint_ipe = dir.join(LINT_IPE);
    if !lint_ipe.is_file() {
        return Ok(LintConfig::default());
    }
    let text =
        crate::io_bounded::read_to_string_capped(&lint_ipe, crate::io_bounded::MANIFEST_READ_CAP)?;
    ipe_lint::read_lint_config(&text, &lint_ipe.display().to_string())
        .map_err(|e| CliError::UsageOwned(e.to_string()))
}

/// Run the linter and print each finding; fail the gate if any survives at or
/// above the gate severity.
// The three output formats (JSON, plain, human) each need their own rendering
// path. Splitting into separate functions would obscure that they all read the
// same report and share the same gate-trip logic, so the body is intentionally
// kept together.
#[allow(clippy::too_many_lines)]
fn report_findings(
    modules: &[SourceModule],
    config: &LintConfig,
    paths: &BTreeMap<Vec<String>, PathBuf>,
    format: cli_args::OutputFormat,
) -> Result<(), CliError> {
    use crate::cli_args::json;
    use cli_args::OutputFormat::{Human, Json, Plain};

    let report = ipe_lint::run(modules, config);
    let source_of: BTreeMap<&[String], &str> = modules
        .iter()
        .map(|m| (m.module.as_slice(), m.source.as_str()))
        .collect();

    match format {
        Json => {
            // Emit a stable JSON object with schema tag and a findings array.
            // Each finding is a JSON object with rule, severity, file, line, col,
            // message, help lines, and whether a fix is available.
            let finding_objs: Vec<String> = report
                .findings
                .iter()
                .map(|f| {
                    let file = paths
                        .get(&f.module)
                        .map_or_else(|| f.module.join("."), |p| p.display().to_string());
                    let source = source_of.get(f.module.as_slice()).copied().unwrap_or("");
                    let severity = config.severity_of(f.rule);
                    // Resolve line/col from the byte offset in source.
                    let (line, col) = byte_to_line_col(source, f.span.lo);
                    let help_arr: Vec<String> = f.help.iter().map(|h| json::string(h)).collect();
                    json::object(&[
                        ("rule", json::string(f.rule)),
                        ("severity", json::string(severity.word())),
                        ("file", json::string(&file)),
                        ("line", line.to_string()),
                        ("col", col.to_string()),
                        ("message", json::string(&f.message)),
                        ("help", json::array(&help_arr)),
                        (
                            "fixable",
                            if f.fix.is_some() || f.sig_fix.is_some() {
                                "true".to_owned()
                            } else {
                                "false".to_owned()
                            },
                        ),
                    ])
                })
                .collect();
            let gate_tripped = report.gate_tripped(config);
            let payload = json::object(&[
                ("schema", json::string("ipe.cli.lint/1")),
                ("findings", json::array(&finding_objs)),
                (
                    "gate_tripped",
                    if gate_tripped {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    },
                ),
            ]);
            screen::emit_machine(Stream::Stdout, &format!("{payload}\n"));
            if gate_tripped {
                return Err(CliError::LintGateFailed);
            }
        }
        Plain => {
            // One line per finding: `<severity>:<file>:<line>:<col>: <message>`.
            let mut lines = String::new();
            for f in &report.findings {
                let file = paths
                    .get(&f.module)
                    .map_or_else(|| f.module.join("."), |p| p.display().to_string());
                let source = source_of.get(f.module.as_slice()).copied().unwrap_or("");
                let severity = config.severity_of(f.rule);
                let (line, col) = byte_to_line_col(source, f.span.lo);
                let _ = writeln!(
                    lines,
                    "{}:{}:{}:{}: {}",
                    severity.word(),
                    file,
                    line,
                    col,
                    f.message
                );
            }
            screen::emit_machine(Stream::Stdout, &lines);
            if report.gate_tripped(config) {
                return Err(CliError::LintGateFailed);
            }
        }
        Human => {
            let mut out = Screen::new(Stream::Stdout);
            if report.findings.is_empty() {
                out.line(Tone::Success, "lint: no findings");
                out.emit();
                return Ok(());
            }

            for finding in &report.findings {
                let file = paths
                    .get(&finding.module)
                    .map_or_else(|| finding.module.join("."), |p| p.display().to_string());
                let source = source_of
                    .get(finding.module.as_slice())
                    .copied()
                    .unwrap_or("");
                let severity = config.severity_of(finding.rule);
                for (role, line) in ipe_lint::render_finding_lines(finding, &file, source, severity)
                {
                    match role {
                        ipe_lint::LineRole::Blank => out.blank(),
                        other => out.line(finding_tone(other), &line),
                    };
                }
                out.blank();
            }

            let count = report.findings.len();
            let gate_tripped = report.gate_tripped(config);
            out.line(
                if gate_tripped {
                    Tone::UserError
                } else {
                    Tone::Text
                },
                &format!("lint: {count} finding{}", if count == 1 { "" } else { "s" }),
            );
            out.emit();

            if gate_tripped {
                return Err(CliError::LintGateFailed);
            }
        }
    }
    Ok(())
}

/// The tone a rendered finding line is painted in.
///
/// The title rule is the finding itself (a user-side issue), the message and
/// snippet are prose, and the teaching help is auxiliary.
const fn finding_tone(role: ipe_lint::LineRole) -> Tone {
    match role {
        ipe_lint::LineRole::Title => Tone::UserError,
        ipe_lint::LineRole::Message | ipe_lint::LineRole::Snippet | ipe_lint::LineRole::Blank => {
            Tone::Text
        }
        ipe_lint::LineRole::Help => Tone::Aux,
    }
}

/// Convert a byte offset into a 1-based `(line, col)` pair by scanning the
/// source. Clamps out-of-range offsets to the nearest valid position.
fn byte_to_line_col(source: &str, offset: u32) -> (usize, usize) {
    let byte = (offset as usize).min(source.len());
    // Walk back to char boundary.
    let mut b = byte;
    while b > 0 && !source.is_char_boundary(b) {
        b -= 1;
    }
    let before = &source[..b];
    let line = before.bytes().filter(|&c| c == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = source[line_start..b].chars().count() + 1;
    (line, col)
}

/// Apply every machine-applicable fix (local and cross-module signature fixes),
/// write the changed sources back to disk, and report what changed.
///
/// Local fixes (single-module, semantics-preserving rewrites such as pipeline
/// style) are applied first via [`ipe_lint::apply_fixes`]. Cross-module
/// signature fixes (call-site rewrites for `prim-param`, `adjacent-bools`) are
/// applied next via [`ipe_lint::apply_sig_fixes`], but crucially fed the
/// already-locally-fixed source for any module that changed. This composes the
/// two passes: sig-fix edits land on top of local edits rather than on the
/// original source, so neither pass's work is lost when both fire on the same
/// module.
///
/// Call sites the change-signature engine cannot rewrite mechanically are
/// printed as manual-review notices — fail-closed.
fn apply_and_report(
    modules: &[SourceModule],
    config: &LintConfig,
    paths: &BTreeMap<Vec<String>, PathBuf>,
    root: &Path,
) -> Result<(), CliError> {
    let local_outcome = ipe_lint::apply_fixes(modules, config);

    // Build the post-local-fix module list: substitute locally-rewritten
    // sources so sig-fix sees the already-improved text.
    let modules_after_local: Vec<SourceModule> = modules
        .iter()
        .map(|m| {
            local_outcome.rewritten.get(&m.module).map_or_else(
                || m.clone(),
                |rewritten| SourceModule {
                    module: m.module.clone(),
                    source: rewritten.clone(),
                },
            )
        })
        .collect();

    let sig_outcome = ipe_lint::apply_sig_fixes(&modules_after_local, config);

    let total = local_outcome.applied + sig_outcome.applied;
    let mut out = Screen::new(Stream::Stdout);
    if total == 0 && sig_outcome.manual_reviews.is_empty() {
        out.line(Tone::Text, "lint --fix: no machine-applicable fixes");
        out.emit();
        return Ok(());
    }

    // Merge: start with local rewrites; compose sig-fix rewrites on top.
    // Sig-fixes were already applied to the locally-fixed source, so inserting
    // them directly gives the fully-composed result per module.
    let mut merged: BTreeMap<Vec<String>, String> = local_outcome.rewritten;
    for (module, rewritten) in sig_outcome.rewritten {
        merged.insert(module, rewritten);
    }

    for (module, rewritten) in &merged {
        let Some(path) = paths.get(module) else {
            continue;
        };
        let backup =
            match crate::rewrite_walked_file(root, path, rewritten, crate::RewriteKind::Lossy) {
                Ok(backup) => backup,
                Err(err) => {
                    // Report the files already rewritten before the failure.
                    out.emit();
                    return Err(err);
                }
            };
        out.line(
            Tone::Text,
            &format!("lint --fix: rewrote {}", path.display()),
        );
        if let Some(backup) = backup {
            out.line(
                Tone::Text,
                &format!("lint --fix: original kept at {}", backup.display()),
            );
        }
    }

    if total > 0 {
        out.line(
            Tone::Success,
            &format!(
                "lint --fix: applied {} fix{}",
                total,
                if total == 1 { "" } else { "es" }
            ),
        );
    }

    for mr in &sig_outcome.manual_reviews {
        out.line(
            Tone::UserError,
            &format!(
                "lint --fix: manual review needed for `{}` ({}) — {}",
                mr.symbol_name, mr.rule, mr.reason
            ),
        );
    }

    out.emit();
    Ok(())
}
