//! `ipe lint [<path>]` (+ `--fix`) — extensible static analysis over `.ipe`
//! source.
//!
//! The command runs over the project rooted at the current directory (or the
//! directory its argument names): it reads the project's own modules from the
//! one [`SourceSnapshot`] of that root — never the injected stdlib — reads an
//! optional `lint.ipe` from the root, runs every enabled rule over the parsed
//! source, and renders each finding compiler-style. A file argument names one
//! module of the project ([`ProjectRoot::target`](crate::project_root::ProjectRoot::target)): every module is still read
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
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ipe_lint::{LINT_CONFIG_FILE as LINT_IPE, LintConfig, SourceModule};

use crate::api_surface::ModulePath;
use crate::driver::{analysis_root, analysis_target, module_missing, working_dir};
use crate::io_bounded::SOURCE_CAP;
use crate::output_dir::held::{BACKUP_SLOTS, BackedUp, HeldDir, Level, RelativeLeaf};
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
/// [`CliError::Usage`] on misuse; [`CliError::ProjectRefused`] for a malformed
/// `lint.ipe`; every refusal of
/// [`analysis_root`] and [`ProjectRoot::target`](crate::project_root::ProjectRoot::target) ([`CliError::NoManifest`],
/// [`CliError::FileOutsideRoot`], …) and of [`SourceSnapshot::read`];
/// [`CliError::LintGateFailed`] when a surviving finding is at or above the
/// gate severity (report path only).
pub(crate) fn run_lint_in(cwd: &Path, rest: &[String]) -> Result<(), CliError> {
    let args = parse_lint_args(rest)?;
    let (root, file) = analysis_root(cwd, args.entry.as_deref().map(Path::new))?;
    let config = load_config(root.path())?;
    let scope = LintScope::of(&analysis_target(&root, file.as_ref())?)?;
    if args.fix {
        return apply_and_report(&scope, &config, &SourceRoots::of(&root));
    }
    report_findings(&scope, &config, args.format)
}

/// The project modules one lint reads, and the one whose findings it reports.
struct LintScope {
    /// Every project module the rules see, in module-path order.
    modules: Vec<SourceModule>,
    /// The file each module was read from, for rendering and rewriting.
    files: BTreeMap<ModulePath, ModuleFile>,
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
        let mut files = BTreeMap::new();
        for (module, held) in held {
            let SourceOrigin::Own(dir) = held.origin() else {
                continue;
            };
            files.insert(
                module.clone(),
                ModuleFile {
                    dir,
                    path: held.path().to_path_buf(),
                },
            );
            modules.push(SourceModule {
                module: module.clone(),
                source: held.text().to_owned(),
            });
        }
        Self {
            modules,
            files,
            focus,
        }
    }

    /// Whether `module` is one whose findings and rewrites this lint reports.
    fn reports(&self, module: &[String]) -> bool {
        self.focus.as_deref().is_none_or(|focus| focus == module)
    }
}

/// A project file one lint read: the source directory it lies under and its path.
struct ModuleFile {
    /// The source directory the file lies under.
    dir: SourceDir,
    /// The file's path, below that directory.
    path: PathBuf,
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
        LintConfigLoadError::Invalid(e) => {
            CliError::ProjectRefused(crate::text::Message::relay(&e))
        }
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

    let LintScope { modules, files, .. } = scope;
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
                    let file = files
                        .get(&f.module)
                        .map_or_else(|| f.module.join("."), |m| m.path.display().to_string());
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
                let file = files
                    .get(&f.module)
                    .map_or_else(|| f.module.join("."), |m| m.path.display().to_string());
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
                let file = files.get(&finding.module).map_or_else(
                    || finding.module.join("."),
                    |m| m.path.display().to_string(),
                );
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
fn apply_and_report(
    scope: &LintScope,
    config: &LintConfig,
    roots: &SourceRoots<'_>,
) -> Result<(), CliError> {
    let LintScope { modules, .. } = scope;
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
    let mut merged: BTreeMap<ModulePath, String> = local_outcome.rewritten;
    for (module, rewritten) in sig_outcome.rewritten {
        merged.insert(module, rewritten);
    }

    // The count below is reached only once every rewritten file is written:
    // a refusal returns before it, so no fix of an unwritten file is counted.
    if let Err(stop) = write_fixes(roots, scope, &merged, &mut out) {
        // Report the files already rewritten before the refusal.
        out.emit();
        return Err(stop.into());
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

/// The held source directories `lint --fix` writes through: the very handles the snapshot read.
struct SourceRoots<'r> {
    /// The held `src/` directory.
    src: &'r HeldDir,
    /// The held `tests/` directory, when the project has one.
    tests: Option<&'r HeldDir>,
}

impl<'r> SourceRoots<'r> {
    /// The source directories `root` holds.
    const fn of(root: &'r ProjectRoot) -> Self {
        Self {
            src: root.src(),
            tests: root.tests(),
        }
    }

    /// The held directory `dir` names, when the project has it.
    const fn held(&self, dir: SourceDir) -> Option<&'r HeldDir> {
        match dir {
            SourceDir::Src => Some(self.src),
            SourceDir::Tests => self.tests,
        }
    }
}

/// Why `lint --fix` left a file as it is and wrote no file after it.
#[derive(Debug, PartialEq, Eq)]
enum FixRefusal {
    /// A rewritten module has no project file this run read.
    NoFile(ModulePath),
    /// The file no longer holds the text the rules judged.
    Changed(PathBuf),
    /// Every backup slot of the file, in the backup directory `dir`, is taken.
    BackupSlotsFull {
        /// The file left as it is.
        path: PathBuf,
        /// The backup directory whose slots are taken.
        dir: PathBuf,
    },
}

impl FixRefusal {
    /// The catalog message stating the refusal.
    fn message(&self) -> text::Message {
        match self {
            Self::NoFile(module) => text::msg::lint_fix_no_file(&module.join(".")),
            Self::Changed(path) => text::msg::lint_fix_changed(&path.display()),
            Self::BackupSlotsFull { path, dir } => {
                text::msg::lint_fix_backups_full(&path.display(), &dir.display(), &BACKUP_SLOTS)
            }
        }
    }
}

/// Why a `lint --fix` batch stopped.
#[derive(Debug)]
enum FixStop {
    /// A file was refused; it and every file not yet written are left as they are.
    Refused(FixRefusal),
    /// A filesystem failure; every file not yet written is left as it is.
    Failed(CliError),
}

impl From<FixStop> for CliError {
    fn from(stop: FixStop) -> Self {
        match stop {
            FixStop::Refused(refusal) => Self::ProjectRefused(refusal.message()),
            FixStop::Failed(error) => error,
        }
    }
}

/// One file a fix batch rewrites: where it lies, the text the rules judged, and the text they produced.
struct PlannedFix<'a> {
    /// The held source directory the file lies under.
    held: &'a HeldDir,
    /// The file below `held`.
    leaf: RelativeLeaf,
    /// The file's path, for reports.
    path: &'a Path,
    /// The text the rules read and judged.
    judged: &'a str,
    /// The text the fixes produced.
    rewritten: &'a str,
}

impl PlannedFix<'_> {
    /// Hold the file's directory and prove the file still holds the judged text.
    ///
    /// Returns the held directory and the identity of the file read, for the
    /// writer's re-proof right before its rename.
    fn judge(&self) -> Result<(Level<'_>, ipe_fs_open::FileId), FixStop> {
        let level = self.held.descend(&self.leaf).map_err(FixStop::Failed)?;
        let (now, id) = level
            .read_file_capped_identified(self.leaf.leaf(), SOURCE_CAP)
            .map_err(FixStop::Failed)?;
        if now != self.judged {
            return Err(FixStop::Refused(FixRefusal::Changed(
                self.path.to_path_buf(),
            )));
        }
        Ok((level, id))
    }
}

/// Plan the rewrite of every module in `merged`; a module with no file the run read is refused.
fn plan_fixes<'a>(
    roots: &SourceRoots<'a>,
    scope: &'a LintScope,
    merged: &'a BTreeMap<ModulePath, String>,
) -> Result<Vec<PlannedFix<'a>>, FixStop> {
    let judged_of: BTreeMap<&[String], &str> = scope
        .modules
        .iter()
        .map(|m| (m.module.as_slice(), m.source.as_str()))
        .collect();
    let mut planned = Vec::with_capacity(merged.len());
    for (module, rewritten) in merged {
        let no_file = || FixStop::Refused(FixRefusal::NoFile(module.clone()));
        let file = scope.files.get(module).ok_or_else(no_file)?;
        let judged = judged_of.get(module.as_slice()).ok_or_else(no_file)?;
        let held = roots.held(file.dir).ok_or_else(no_file)?;
        let leaf = RelativeLeaf::under(held.path(), &file.path).map_err(FixStop::Failed)?;
        planned.push(PlannedFix {
            held,
            leaf,
            path: &file.path,
            judged,
            rewritten,
        });
    }
    Ok(planned)
}

/// Write every rewritten module of `merged` through the held writer, keeping each original in a backup slot.
///
/// The batch is all-or-nothing up to the first write: every file is planned
/// and judged before any is written, so a module with no file, a file edited
/// since the lint read it, or a level that cannot be held stops the batch with
/// nothing written. A write that is refused or fails stops the batch too,
/// leaving the files after it as they are: signature fixes rewrite a
/// definition and its callers in different modules, so writing the rest past
/// one refused file would leave callers out of step with the definition.
fn write_fixes(
    roots: &SourceRoots<'_>,
    scope: &LintScope,
    merged: &BTreeMap<ModulePath, String>,
    out: &mut Screen,
) -> Result<(), FixStop> {
    let planned = plan_fixes(roots, scope, merged)?;
    for fix in &planned {
        fix.judge()?;
    }
    for fix in &planned {
        let (level, id) = fix.judge()?;
        let fill = |file: &mut std::fs::File| file.write_all(fix.rewritten.as_bytes());
        let backups = level.path().join(crate::driver::BACKUP_DIR);
        match level
            .replace_backed_up(
                fix.leaf.leaf().as_os_str(),
                id,
                fix.judged,
                SOURCE_CAP,
                fill,
            )
            .map_err(FixStop::Failed)?
        {
            BackedUp::Done(backup) => {
                out.line(
                    Tone::Text,
                    &format!("lint --fix: rewrote {}", fix.path.display()),
                );
                out.line(
                    Tone::Text,
                    &format!(
                        "lint --fix: original kept at {}",
                        backups.join(backup.slot().as_os_str()).display()
                    ),
                );
            }
            BackedUp::Changed => {
                return Err(FixStop::Refused(FixRefusal::Changed(
                    fix.path.to_path_buf(),
                )));
            }
            BackedUp::BackupSlotsFull => {
                return Err(FixStop::Refused(FixRefusal::BackupSlotsFull {
                    path: fix.path.to_path_buf(),
                    dir: backups,
                }));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::output_dir::held::{Synced, set_sync_hook};

    /// A fresh `src/` directory holding `Main.ipe` with `text`, and the directory's held handle.
    #[allow(clippy::expect_used)] // a fixture that cannot be built is a broken test host
    fn src_with_main(tag: &str, text: &str) -> (PathBuf, HeldDir) {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_lint_fix_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(&src).expect("make src");
        let src = std::fs::canonicalize(&src).expect("canonicalize src");
        std::fs::write(src.join("Main.ipe"), text).expect("write Main.ipe");
        let held = HeldDir::open(&src).expect("open src").expect("src exists");
        (src, held)
    }

    /// A scope over `Main` (and `Other`, read with no file) judged at `judged`.
    fn scope_of(src: &Path, judged: &str) -> LintScope {
        let module = |name: &str| vec![name.to_owned()];
        LintScope {
            modules: vec![
                SourceModule {
                    module: module("Main"),
                    source: judged.to_owned(),
                },
                SourceModule {
                    module: module("Other"),
                    source: "module Other exposing (..)\n".to_owned(),
                },
            ],
            files: BTreeMap::from([(
                module("Main"),
                ModuleFile {
                    dir: SourceDir::Src,
                    path: src.join("Main.ipe"),
                },
            )]),
            focus: None,
        }
    }

    fn read(path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    /// An edit landing between the judgement and the rename survives, is refused, and leaves no backup slot.
    #[test]
    #[allow(clippy::expect_used)] // the hook's concurrent edit must land for the refusal to mean anything
    fn fix_changed_reported_not_overwritten() {
        let (src, held) = src_with_main("changed", "old\n");
        let main = src.join("Main.ipe");
        let roots = SourceRoots {
            src: &held,
            tests: None,
        };
        let scope = scope_of(&src, "old\n");
        let merged = BTreeMap::from([(vec!["Main".to_owned()], "new\n".to_owned())]);

        // Control: the same batch, with no edit in the window, writes and keeps the original.
        let mut out = Screen::new(Stream::Stdout);
        let written = write_fixes(&roots, &scope, &merged, &mut out);
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(read(&main).as_deref(), Some("new\n"));
        let backups = src.join(crate::driver::BACKUP_DIR);
        assert_eq!(
            read(&backups.join("Main.ipe.bak")).as_deref(),
            Some("old\n")
        );
        std::fs::write(&main, "old\n").expect("reset Main.ipe");
        std::fs::remove_file(backups.join("Main.ipe.bak")).expect("clear the control's slot");

        let target = main.clone();
        set_sync_hook(Some(Box::new(move |what: Synced, _at: &Path| {
            if what == Synced::Staged {
                std::fs::write(&target, "edited\n").expect("concurrent edit");
            }
        })));
        let mut out = Screen::new(Stream::Stdout);
        let stopped = write_fixes(&roots, &scope, &merged, &mut out);
        set_sync_hook(None);

        assert!(
            matches!(&stopped, Err(FixStop::Refused(FixRefusal::Changed(path))) if *path == main),
            "{stopped:?}"
        );
        assert_eq!(read(&main).as_deref(), Some("edited\n"));
        assert_eq!(read(&backups.join("Main.ipe.bak")), None);
        let _ = std::fs::remove_dir_all(src.parent().unwrap_or(&src));
    }

    /// A rewritten module with no file is refused before any file is written, so nothing is counted.
    #[test]
    fn fix_missing_path_refused_and_not_counted() {
        let (src, held) = src_with_main("no_path", "old\n");
        let main = src.join("Main.ipe");
        let roots = SourceRoots {
            src: &held,
            tests: None,
        };
        let scope = scope_of(&src, "old\n");
        // `Main` sorts before `Other`: a skipped `Other` would leave `Main` written.
        let merged = BTreeMap::from([
            (vec!["Main".to_owned()], "new\n".to_owned()),
            (vec!["Other".to_owned()], "module Other\n".to_owned()),
        ]);

        let mut out = Screen::new(Stream::Stdout);
        let stopped = write_fixes(&roots, &scope, &merged, &mut out);

        assert!(
            matches!(
                &stopped,
                Err(FixStop::Refused(FixRefusal::NoFile(module))) if *module == ["Other"]
            ),
            "{stopped:?}"
        );
        assert_eq!(read(&main).as_deref(), Some("old\n"));
        assert!(!src.join(crate::driver::BACKUP_DIR).exists());

        // Control: with only `Main` the batch writes it.
        let merged = BTreeMap::from([(vec!["Main".to_owned()], "new\n".to_owned())]);
        let written = write_fixes(&roots, &scope, &merged, &mut out);
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(read(&main).as_deref(), Some("new\n"));
        let _ = std::fs::remove_dir_all(src.parent().unwrap_or(&src));
    }
}
