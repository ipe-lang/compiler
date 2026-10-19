//! `ipe lint [<path>]` (+ `--fix`) — extensible static analysis over `.ipe`
//! source.
//!
//! The command runs over the project rooted at the current directory (or the
//! directory its argument names): it reads the project's own modules from the
//! one [`SourceSnapshot`] of that root — never the injected stdlib — reads an
//! optional `lint.ipe` from the root, runs every enabled rule over the parsed
//! source, and renders each finding compiler-style. A file argument names one
//! module of the project ([`ProjectRoot::target`]): every module is still read
//! for context, but only that module's findings are reported, and `--fix`
//! rewrites only its file. With `--fix` every machine-applicable
//! (semantics-preserving) rewrite is applied and reported; otherwise a
//! surviving finding at or above the configured gate severity exits non-zero
//! for CI.
//!
//! `--json` emits findings as `{"schema":"ipe.cli.lint/1","findings":[…]}`.
//! `--plain` prints one line per finding: `<severity>:<file>:<line>:<col>: <message>`.
//! Both forms are mutually exclusive with each other and fail closed against
//! `--fix` (a data form must not trigger mutations — the same rule `health` uses).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe_lint::{LINT_CONFIG_FILE as LINT_IPE, LintConfig, SourceModule};

use crate::api_surface::ModulePath;
use crate::driver::{analysis_root, analysis_target, module_missing, working_dir};
use crate::project_root::{AnalysisTarget, ProjectRoot, SourceDir};
use crate::screen::{self, Screen, Stream, Tone};
use crate::source_snapshot::{Limits, SnapshotModule, SourceOrigin, SourceSnapshot};
use crate::{CliError, cli_args, text};

/// Parsed `ipe lint` arguments.
pub(crate) struct LintArgs {
    /// The path to lint: a module file of the project or a project directory.
    /// Defaults to the current directory's project.
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
/// [`CliError::Usage`] on an unknown flag, a second positional, or
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
                    return Err(CliError::Usage(text::msg::lint_single_path()));
                }
                entry = Some(positional.to_owned());
            }
        }
    }
    let format = format.unwrap_or_default();
    if fix && format != cli_args::OutputFormat::Human {
        return Err(CliError::Usage(text::msg::lint_fix_with_format()));
    }
    Ok(LintArgs { entry, fix, format })
}

/// `ipe lint [<path>]` — run the linter, printing findings (or applying fixes).
///
/// # Errors
/// Every refusal of [`run_lint_in`] over the current directory.
pub(crate) fn run_lint(rest: &[String]) -> Result<(), CliError> {
    run_lint_in(&working_dir()?, rest)
}

/// [`run_lint`] with `cwd` as the current directory.
///
/// # Errors
/// [`CliError::Usage`] on misuse or a malformed `lint.ipe`; every refusal of
/// [`analysis_root`] and [`ProjectRoot::target`] ([`CliError::NoManifest`],
/// [`CliError::FileOutsideRoot`], …) and of [`SourceSnapshot::read`];
/// [`CliError::LintGateFailed`] when a surviving finding is at or above the
/// gate severity (report path only).
pub(crate) fn run_lint_in(cwd: &Path, rest: &[String]) -> Result<(), CliError> {
    let args = parse_lint_args(rest)?;
    let (root, file) = analysis_root(cwd, args.entry.as_deref().map(Path::new))?;
    let config = load_config(root.path())?;
    let scope = LintScope::of(&analysis_target(&root, file.as_ref())?)?;
    if args.fix {
        return apply_and_report(&scope, &config, root.path());
    }
    report_findings(&scope, &config, args.format)
}

/// The project modules one lint reads, and the one whose findings it reports.
struct LintScope {
    /// Every project module the rules see, in module-path order.
    modules: Vec<SourceModule>,
    /// The file each module was read from, for rendering and rewriting.
    paths: BTreeMap<ModulePath, PathBuf>,
    /// The module a file argument named; `None` reports every module.
    focus: Option<ModulePath>,
}

impl LintScope {
    /// The modules `target` reads, all from one snapshot of its root.
    ///
    /// The whole project, or one of its `src/` modules, reads the build's own
    /// modules; a `tests/` module reads its test program's universe. Injected
    /// stdlib and FFI interface text is never linted.
    ///
    /// # Errors
    /// Every refusal of [`SourceSnapshot::read`] and
    /// [`SourceSnapshot::test_view`]; [`CliError::Io`] (`NotFound`) for a
    /// `tests/` module the snapshot does not hold.
    fn of(target: &AnalysisTarget<'_>) -> Result<Self, CliError> {
        let (AnalysisTarget::Project(root) | AnalysisTarget::Module { root, .. }) = target;
        let snapshot = SourceSnapshot::read(root, Limits::DEFAULT)?;
        match target {
            AnalysisTarget::Project(_) => Ok(Self::over(snapshot.modules(), None)),
            AnalysisTarget::Module {
                dir: SourceDir::Src,
                module,
                ..
            } => Ok(Self::over(snapshot.modules(), Some(module.clone()))),
            AnalysisTarget::Module {
                dir: SourceDir::Tests,
                module,
                ..
            } => {
                let Some(entry) = snapshot.test_entry(module) else {
                    return Err(module_missing(root, SourceDir::Tests, module));
                };
                let view = SourceSnapshot::test_view(entry)?;
                Ok(Self::over(view.modules(), Some(view.entry().clone())))
            }
        }
    }

    /// The project's own modules of `held`, reporting `focus` alone when given.
    fn over(held: &BTreeMap<ModulePath, SnapshotModule>, focus: Option<ModulePath>) -> Self {
        let mut modules = Vec::new();
        let mut paths = BTreeMap::new();
        for (module, held) in held {
            if !matches!(held.origin(), SourceOrigin::Own(_)) {
                continue;
            }
            paths.insert(module.clone(), held.path().to_path_buf());
            modules.push(SourceModule {
                module: module.clone(),
                source: held.text().to_owned(),
            });
        }
        Self {
            modules,
            paths,
            focus,
        }
    }

    /// Whether `module` is one whose findings and rewrites this lint reports.
    fn reports(&self, module: &[String]) -> bool {
        self.focus.as_deref().is_none_or(|focus| focus == module)
    }
}

/// Read `lint.ipe` from the project root `dir`, returning defaults when none exists.
///
/// The read goes through [`ipe_lint::load_lint_config`], the one bounded,
/// open-once reader the language server shares. `lint.ipe` is found by
/// convention, not named by the user, so a symlink, FIFO, device, or
/// directory at that name is [`CliError::SourceRefused`] and an oversized
/// one [`CliError::FileTooLarge`] — never followed, waited on, or ignored.
fn load_config(dir: &Path) -> Result<LintConfig, CliError> {
    use ipe_lint::{LintConfigLoadError, WorkspaceReadError};

    use crate::io_bounded::{SourceRefusal, access_error, source_refused};

    let path = dir.join(LINT_IPE);
    ipe_lint::load_lint_config(dir).map_err(|e| match e {
        LintConfigLoadError::Read(WorkspaceReadError::Unreadable(source)) => {
            access_error(&path, source)
        }
        LintConfigLoadError::Read(WorkspaceReadError::NotAFile) => {
            source_refused(&path, SourceRefusal::NotRegularFile)
        }
        LintConfigLoadError::Read(WorkspaceReadError::NotUtf8) => CliError::Io {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid UTF-8"),
        },
        LintConfigLoadError::Read(WorkspaceReadError::TooLarge { max }) => CliError::FileTooLarge {
            path: path.clone(),
            max,
        },
        LintConfigLoadError::Invalid(e) => CliError::Usage(crate::text::Message::relay(&e)),
    })
}

/// Run the linter over `scope` and print each finding it reports; fail the gate
/// if any reported finding survives at or above the gate severity.
// The three output formats (JSON, plain, human) each need their own rendering
// path. Splitting into separate functions would obscure that they all read the
// same report and share the same gate-trip logic, so the body is intentionally
// kept together.
#[allow(clippy::too_many_lines)]
fn report_findings(
    scope: &LintScope,
    config: &LintConfig,
    format: cli_args::OutputFormat,
) -> Result<(), CliError> {
    use crate::cli_args::json;
    use cli_args::OutputFormat::{Human, Json, Plain};

    let LintScope { modules, paths, .. } = scope;
    let Ok(mut report) = ipe_lint::run(modules, config, &ipe_lint::NeverCancel);
    report.findings.retain(|f| scope.reports(&f.module));
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
///
/// A lint focused on one module rewrites that module's file alone: a
/// signature fix whose call-site rewrites reach another module is withheld
/// whole, and reported, so no partial change leaves a caller out of step.
fn apply_and_report(scope: &LintScope, config: &LintConfig, root: &Path) -> Result<(), CliError> {
    let LintScope { modules, paths, .. } = scope;
    let mut local_outcome = ipe_lint::apply_fixes(modules, config);
    if scope.focus.is_some() {
        local_outcome
            .rewritten
            .retain(|module, _| scope.reports(module));
    }

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

    let mut sig_outcome = ipe_lint::apply_sig_fixes(&modules_after_local, config);
    let mut out = Screen::new(Stream::Stdout);
    if sig_outcome
        .rewritten
        .keys()
        .any(|module| !scope.reports(module))
    {
        sig_outcome.rewritten.clear();
        sig_outcome.applied = 0;
        out.line(
            Tone::UserError,
            "lint --fix: signature fixes withheld: they rewrite modules other than the one named; run lint --fix without a file to apply them",
        );
    }

    let total = if scope.focus.is_some() {
        local_outcome.rewritten.len() + sig_outcome.rewritten.len()
    } else {
        local_outcome.applied + sig_outcome.applied
    };
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

    if total > 0 && scope.focus.is_none() {
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
